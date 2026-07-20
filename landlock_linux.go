//go:build linux

/*-
 * Copyright 2024, Ghostunnel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type portRuleFunc = func(port uint16) landlock.NetRule

var defaultReadWritePaths = []string{
	"/dev",     // /dev/log syslog socket, /dev/urandom, /dev/null
	"/run",     // sd_notify socket, journald socket, runtime state
	"/var/run", // legacy alias of /run; some syslog daemons listen here
	"/proc",    // Go runtime: /proc/self/* for GC and scheduler
	"/tmp",     // temporary files (e.g. spooled writes, Go runtime)
}

var defaultReadOnlyPaths = []string{
	"/sys",                             // Go runtime: cgroup info for GOMAXPROCS, CPU topology
	"/etc",                             // DNS config, hosts, nsswitch, localtime, distro CA bundles
	"/usr/share/zoneinfo",              // tzdata, referenced via /etc/localtime symlink
	"/usr/share/ca-certificates",       // Debian/Ubuntu CA cert source files
	"/usr/local/share/ca-certificates", // locally-installed CA certs (Debian/Ubuntu)
	"/var/lib/ca-certificates",         // openSUSE/SLES CA bundle location
}

// setupLandlock processes flags given to the process and generates an
// appropriate landlock rule configuration to limit our privileges.
func setupLandlock() error {
	fsRules := []landlock.Rule{}
	netRules := []landlock.Rule{}

	// Extra RW paths registered by init() hooks (e.g. GOCOVERDIR for
	// coverage-instrumented builds).
	for _, path := range extraRWPaths {
		fsRules = append(fsRules, landlock.RWDirs(path))
	}

	// DNS over TCP as a fallback path for Go's resolver when a UDP response
	// is truncated. UDP DNS is not gated by landlock net rules.
	netRules = append(netRules, landlock.ConnectTCP(53))

	// Default RW FS rules. Some paths we need always accessible for syslog and
	// for creating runtime/temporary files. Note that syslog can be in multiple
	// places not just /dev/log, e.g. /var/run is an option.
	for _, path := range defaultReadWritePaths {
		fsRules = append(fsRules, landlock.RWDirs(path).IgnoreIfMissing())
	}

	// Default RO FS rules. Some paths we need always accessible for name
	// resolution or time zones. For this purpose we keep /etc accessible. Note
	// that we could have chosen to limit ourselves to specific files (e.g.
	// /etc/nsswitch.conf, /etc/gai.conf), but it's difficult to enumerate the
	// exact set of files required in every conceivable situation.
	for _, path := range defaultReadOnlyPaths {
		fsRules = append(fsRules, landlock.RODirs(path).IgnoreIfMissing())
	}

	// When ACME is enabled, certmagic persists certificates and keys to
	// $XDG_DATA_HOME/certmagic (defaulting to $HOME/.local/share/certmagic).
	// Grant RW on the parent dir so certmagic can create and populate the
	// certmagic/ subdirectory on first use. The path is per-user so it's not
	// safe to add unconditionally. Outbound access to the ACME CA URL (for
	// directory/order/finalize and cert downloads) is granted via the
	// ConnectTCP loop below using the configured --auto-acme-ca /
	// --auto-acme-testca URLs, falling back to Let's Encrypt on tcp/443 when
	// neither is set. TLS-ALPN-01 challenge traffic is inbound on the
	// listener and is already covered by its BindTCP rule.
	if serverAutoACMEFQDN != nil && *serverAutoACMEFQDN != "" {
		fsRules = append(fsRules, landlock.RWDirs(filepath.Dir(certmagicDataDir())).IgnoreIfMissing())
		if (serverAutoACMEProdCA == nil || *serverAutoACMEProdCA == "") &&
			(serverAutoACMETestCA == nil || *serverAutoACMETestCA == "") {
			netRules = append(netRules, landlock.ConnectTCP(443))
		}
	}

	// SSL_CERT_FILE and SSL_CERT_DIR override Go's compiled-in CA bundle search
	// paths (see crypto/x509/root_unix.go), so if an operator has set these the
	// default RO paths above won't cover what Go actually reads.
	if f := os.Getenv("SSL_CERT_FILE"); f != "" {
		fsRules = append(fsRules, rulesFromFile(f)...)
	}
	if d := os.Getenv("SSL_CERT_DIR"); d != "" {
		for _, dir := range strings.Split(d, ":") {
			if dir == "" {
				continue
			}
			fsRules = append(fsRules, rulesFromCertDir(dir)...)
		}
	}

	// Process string flags containing addresses or URLs.
	for _, addr := range []*string{
		serverListenAddress,
		clientListenAddress,
		statusAddress,
	} {
		if addr == nil || len(*addr) == 0 {
			continue
		}

		fsRule, netRule, err := ruleFromStringAddress(*addr, landlock.BindTCP)
		if err != nil {
			return fmt.Errorf("processing argument %q for landlock rule: %w", *addr, err)
		}
		if fsRule != nil {
			fsRules = append(fsRules, fsRule)
		}
		if netRule != nil {
			netRules = append(netRules, netRule)
		}
	}

	for _, addr := range []*string{
		serverForwardAddress,
		serverStatusTargetAddress,
		clientForwardAddress,
		useWorkloadAPIAddr,
		metricsURL,
		serverAutoACMEProdCA,
		serverAutoACMETestCA,
	} {
		if addr == nil || len(*addr) == 0 {
			continue
		}

		fsRule, netRule, err := ruleFromStringAddress(*addr, landlock.ConnectTCP)
		if err != nil {
			return fmt.Errorf("processing argument %q for landlock rule: %w", *addr, err)
		}
		if fsRule != nil {
			fsRules = append(fsRules, fsRule)
		}
		if netRule != nil {
			netRules = append(netRules, netRule)
		}
	}

	// Process string flags containing file paths.
	for _, path := range []*string{
		serverAllowPolicy,
		clientAllowPolicy,
		keystorePath,
		certPath,
		keyPath,
		caBundlePath,
	} {
		if path == nil || len(*path) == 0 {
			continue
		}
		fsRules = append(fsRules, rulesFromFile(*path)...)
	}

	// Process net.TCPAddr flags.
	for _, addr := range []**net.TCPAddr{metricsGraphite} {
		if addr == nil || *addr == nil {
			continue
		}

		rule, err := ruleFromTCPAddress(*addr, landlock.ConnectTCP)
		if err != nil {
			return fmt.Errorf("processing argument %q for landlock rule: %w", *addr, err)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	// Outbound HTTP from Go's net/http transport (certmagic ACME calls)
	// honors the HTTP_PROXY / HTTPS_PROXY env vars at request time. If
	// they're set, allow outbound connect to the proxy.
	for _, u := range proxyURLsFromEnv() {
		rule, err := ruleFromURL(u, landlock.ConnectTCP)
		if err != nil {
			return fmt.Errorf("processing proxy env URL %q for landlock rule: %w", u, err)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	// Process url.URL flags.
	for _, url := range []**url.URL{clientProxy} {
		if url == nil || *url == nil {
			continue
		}

		rule, err := ruleFromURL(*url, landlock.ConnectTCP)
		if err != nil {
			return fmt.Errorf("processing argument %q for landlock rule: %w", *url, err)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	// Log if kernel doesn't support net rules so we don't just silently downgrade
	abiVersion, err := llsys.LandlockGetABIVersion()
	if err != nil || abiVersion < 4 {
		logger.Printf("note: kernel does not support landlock net rules, sandboxing will be limited")
	}

	// Enable best-effort mode: If the kernel doesn't support ABI v8, then go-landlock
	// will enforce as much as possible given the ABI version that *is* available. Note
	// that normally no error will be returned in best-effort mode, but we capture and
	// return it here anyway to be defensive.
	config := landlock.V8.BestEffort()

	err = config.RestrictPaths(fsRules...)
	if err != nil {
		return err
	}
	return config.RestrictNet(netRules...)
}

// ruleFromStringAddress turns a flag-supplied address string into a landlock
// rule. Handles unix sockets (RW on the socket's parent dir), systemd/launchd
// socket activation (no rule needed; the FD is inherited), HTTP/HTTPS URLs,
// and host:port forms. ruleFromPort selects bind vs connect semantics.
//
// Returns at most one non-nil rule: an FS rule for unix-socket addresses,
// otherwise a net rule. Callers must dispatch each into the correct slice —
// passing an FS rule to RestrictNet (or vice versa) intersects to zero access
// inside go-landlock and is silently dropped.
func ruleFromStringAddress(addr string, ruleFromPort portRuleFunc) (landlock.Rule, landlock.Rule, error) {
	if strings.HasPrefix(addr, "unix:") {
		path := addr[5:]
		if path == "" {
			// socket.ParseAddress accepts "unix:" with an empty path;
			// reject here so we don't silently grant RW on the CWD via
			// filepath.Dir("") == "." before the bind error surfaces.
			return nil, nil, errors.New("unix socket path is empty")
		}
		// Grant RW on the parent directory rather than the socket file
		// itself: the file does not exist at bind(2) time, and shutdown
		// may unlink it. No IgnoreIfMissing — if the operator-supplied
		// parent is missing at startup, fail loud (landlock setup errors
		// and the warning at the call site fires) rather than silently
		// dropping the rule and denying bind/connect later.
		return landlock.RWDirs(filepath.Dir(path)), nil, nil
	}
	if strings.HasPrefix(addr, "systemd:") || strings.HasPrefix(addr, "launchd:") {
		// Socket activation - no rule needed
		return nil, nil, nil
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, nil, err
		}
		rule, err := ruleFromURL(u, ruleFromPort)
		return nil, rule, err
	}
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return nil, nil, errors.New("unable to extract port number from address")
	}
	port, err := strconv.ParseUint(parts[len(parts)-1], 10, 16)
	if err != nil {
		return nil, nil, errors.New("unable to extract port number from address")
	}
	if port == 0 {
		return nil, nil, errors.New("unable to extract port number from address")
	}
	return nil, ruleFromPort(uint16(port)), nil
}

// ruleFromTCPAddress turns a *net.TCPAddr (from already-parsed flags like
// --metrics-graphite) into a port-based landlock rule. ruleFromPort selects
// bind vs connect semantics.
func ruleFromTCPAddress(addr *net.TCPAddr, ruleFromPort portRuleFunc) (landlock.Rule, error) {
	if addr.Port == 0 {
		return nil, errors.New("unable to extract port number from address")
	}
	return ruleFromPort(uint16(addr.Port)), nil
}

// ruleFromURL turns a *url.URL into a port-based landlock rule, defaulting
// the port by scheme when none is explicit: 80 for http, 443 for https,
// 1080 for socks5/socks5h. ruleFromPort selects bind vs connect semantics.
func ruleFromURL(u *url.URL, ruleFromPort portRuleFunc) (landlock.Rule, error) {
	port := u.Port()
	if len(port) == 0 {
		switch u.Scheme {
		case "http":
			return ruleFromPort(uint16(80)), nil
		case "https":
			return ruleFromPort(uint16(443)), nil
		case "socks5", "socks5h":
			return ruleFromPort(uint16(1080)), nil
		}
	}
	numericPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, errors.New("unable to extract port number from address")
	}
	if numericPort == 0 {
		return nil, errors.New("unable to extract port number from address")
	}
	return ruleFromPort(uint16(numericPort)), nil
}

// proxyURLsFromEnv returns deduplicated proxy URLs that Go's net/http would
// honor via HTTP_PROXY / HTTPS_PROXY (and the lowercase variants) at request
// time. NO_PROXY is a bypass list, not a destination, so it needs no rule.
// Mirrors the fallback in golang.org/x/net/http/httpproxy: if the value isn't
// a URL with a recognized scheme, retry with "http://" prepended.
func proxyURLsFromEnv() []*url.URL {
	var urls []*url.URL
	seen := make(map[string]bool)
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		v := os.Getenv(name)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		u, err := url.Parse(v)
		if err != nil || u.Host == "" ||
			(u.Scheme != "http" && u.Scheme != "https" &&
				u.Scheme != "socks5" && u.Scheme != "socks5h") {
			u, err = url.Parse("http://" + v)
			if err != nil || u.Host == "" {
				continue
			}
		}
		urls = append(urls, u)
	}
	return urls
}

// rulesFromFile returns RO rules covering the parent directory of path, and
// (if path is a symlink) the parent directory of the symlink target. We grant
// the parent rather than the file itself so the file can be replaced
// atomically (write-new-then-rename) and reloaded without breaking the rule.
func rulesFromFile(path string) []landlock.Rule {
	rules := []landlock.Rule{landlock.RODirs(filepath.Dir(path)).IgnoreIfMissing()}
	if target, err := filepath.EvalSymlinks(path); err == nil && target != path {
		rules = append(rules, landlock.RODirs(filepath.Dir(target)).IgnoreIfMissing())
	}
	return rules
}

// rulesFromCertDir returns an RO rule for dir, plus an RO rule for the parent
// directory of every readable entry whose symlinks resolve. Distros commonly
// populate cert directories (e.g. /etc/ssl/certs) with symlinks pointing into
// a vendor-specific bundle location, and Go's crypto/x509 follows those
// symlinks when scanning SSL_CERT_DIR — so we need rules covering the
// eventual targets too. Plain files and subdirs produce redundant rules,
// which landlock dedupes at the kernel level.
func rulesFromCertDir(dir string) []landlock.Rule {
	rules := []landlock.Rule{landlock.RODirs(dir).IgnoreIfMissing()}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return rules
	}
	for _, entry := range entries {
		target, err := filepath.EvalSymlinks(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		rules = append(rules, landlock.RODirs(filepath.Dir(target)).IgnoreIfMissing())
	}
	return rules
}

// certmagicDataDir mirrors the path resolution logic in certmagic's
// FileStorage so the landlock rule covers exactly what the library writes to.
// See vendor/github.com/caddyserver/certmagic/filestorage.go (dataDir).
func certmagicDataDir() string {
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		return filepath.Join(xdg, "certmagic")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	return filepath.Join(home, ".local", "share", "certmagic")
}
