/*-
 * Copyright 2015 Square Inc.
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
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/ghostunnel/ghostunnel/auth"
	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/ghostunnel/ghostunnel/socket"
	"github.com/ghostunnel/ghostunnel/wildcard"

	kingpin "github.com/alecthomas/kingpin/v2"
	graphite "github.com/cyberdelia/go-metrics-graphite"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/rcrowley/go-metrics"
	sqmetrics "github.com/square/go-sq-metrics"
	connectproxy "github.com/wrouesnel/go.connect-proxy-scheme"
	netproxy "golang.org/x/net/proxy"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version              = "master"
	defaultMetricsPrefix = "ghostunnel"
)

// Optional flags (enabled conditionally based on build)
var (
	keychainIdentity     *string //nolint:unused
	keychainIssuer       *string //nolint:unused
	keychainRequireToken *bool   //nolint:unused
	pkcs11Module         *string //nolint:unused
	pkcs11TokenLabel     *string //nolint:unused
	pkcs11PIN            *string //nolint:unused
	disableLandlock      *bool   //nolint:unused
)

// Main flags (always supported)
var (
	app = kingpin.New("ghostunnel", "A simple TLS proxy with mutual authentication for securing non-TLS services.")

	// Server flags
	serverCommand             = app.Command("server", "Server mode (TLS listener -> plain TCP/UNIX target).")
	serverListenAddress       = serverCommand.Flag("listen", "Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).").PlaceHolder("ADDR").Required().String()
	serverForwardAddress      = serverCommand.Flag("target", "Address to forward connections to (can be HOST:PORT or unix:PATH).").PlaceHolder("ADDR").Required().String()
	serverStatusTargetAddress = serverCommand.Flag("target-status", "Address to target for status checking downstream healthchecks. Defaults to a TCP healthcheck if this flag is not passed.").Default("").String()
	serverProxyProtocol       = serverCommand.Flag("proxy-protocol", "Enable PROXY protocol v2 (connection info only, equivalent to --proxy-protocol-mode=conn).").Bool()
	serverProxyProtocolMode   = serverCommand.Flag("proxy-protocol-mode", "PROXY protocol v2 mode: conn (connection info only), tls (add TLS version/ALPN/SNI metadata), tls-full (add TLS metadata and client certificate). Mutually exclusive with --proxy-protocol.").Enum("conn", "tls", "tls-full")
	serverUnsafeTarget        = serverCommand.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	serverAllowAll            = serverCommand.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	serverAllowedCNs          = serverCommand.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	serverAllowedOUs          = serverCommand.Flag("allow-ou", "Allow clients with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	serverAllowedDNSs         = serverCommand.Flag("allow-dns", "Allow clients with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	serverAllowedIPs          = serverCommand.Flag("allow-ip", "").Hidden().PlaceHolder("SAN").IPList()
	serverAllowedURIs         = serverCommand.Flag("allow-uri", "Allow clients with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
	serverAllowSpkiPin        = serverCommand.Flag("allow-spki-pin", "Allow clients matching the given SPKI pin of the form <algo>:<base64-digest> (repeatable, e.g. sha256:...). This is out-of-band key pinning: the client is authenticated by the pin alone. Its certificate chain, validity period, and hostname are not verified. Mutually exclusive with other access control flags.").PlaceHolder("PIN").Strings()
	serverAllowPolicy         = serverCommand.Flag("allow-policy", "Allow passing the location of an OPA bundle.").PlaceHolder("BUNDLE").String()
	serverAllowQuery          = serverCommand.Flag("allow-query", "Allow defining a query to validate against the client certificate and the Rego policy.").PlaceHolder("QUERY").String()
	serverDisableAuth         = serverCommand.Flag("disable-authentication", "Disable client authentication, no client certificate will be required.").Default("false").Bool()
	serverAutoACMEFQDN        = serverCommand.Flag("auto-acme-cert", "Automatically obtain a certificate via ACME for the specified FQDN").PlaceHolder("FQDN").String()
	serverAutoACMEEmail       = serverCommand.Flag("auto-acme-email", "Email address associated with all ACME requests").PlaceHolder("EMAIL").String()
	serverAutoACMEAgreedTOS   = serverCommand.Flag("auto-acme-agree-to-tos", "Agree to the Terms of Service of the ACME CA").Default("false").Bool()
	serverAutoACMEProdCA      = serverCommand.Flag("auto-acme-ca", "Specify the URL to the ACME CA. Defaults to Let's Encrypt if not specified.").PlaceHolder("https://some-acme-ca.example.com/").String()
	serverAutoACMETestCA      = serverCommand.Flag("auto-acme-testca", "Specify the URL to the ACME CA's Test/Staging environment. If set, all requests will go to this CA and --auto-acme-ca will be ignored.").PlaceHolder("https://testing.some-acme-ca.example.com/").String()
	// Hidden: override certmagic's background renewal-check interval. Only
	// used by the ACME integration test to observe renewal within seconds.
	serverAutoACMERenewCheckInterval = serverCommand.Flag("auto-acme-renew-check-interval", "").Hidden().Duration()
	// Hidden: override the port certmagic binds for TLS-ALPN-01 during
	// initial issuance. Production should use 443 so the public ACME CA can
	// reach it; the integration test sets this so it can run without root.
	serverAutoACMEAltTLSALPNPort = serverCommand.Flag("auto-acme-alt-tls-alpn-port", "").Hidden().Int()

	// Client flags
	clientCommand       = app.Command("client", "Client mode (plain TCP/UNIX listener -> TLS target).")
	clientListenAddress = clientCommand.Flag("listen", "Address and port to listen on (can be HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME).").PlaceHolder("ADDR").Required().String()
	// Note: can't use .TCP() for clientForwardAddress because we need to set the original string in tls.Config.ServerName.
	clientForwardAddress = clientCommand.Flag("target", "Address to forward connections to (must be HOST:PORT).").PlaceHolder("ADDR").Required().String()
	clientUnsafeListen   = clientCommand.Flag("unsafe-listen", "If set, does not limit listen to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	clientServerName     = clientCommand.Flag("override-server-name", "If set, overrides the server name used for hostname verification.").PlaceHolder("NAME").String()
	clientProxy          = clientCommand.Flag("proxy", "If set, connect to target over given proxy (HTTP CONNECT or SOCKS5). Must be a proxy URL.").PlaceHolder("URL").URL()
	clientAllowedCNs     = clientCommand.Flag("verify-cn", "Allow servers with given common name (can be repeated).").PlaceHolder("CN").Strings()
	clientAllowedOUs     = clientCommand.Flag("verify-ou", "Allow servers with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	clientAllowedDNSs    = clientCommand.Flag("verify-dns", "Allow servers with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	clientAllowedIPs     = clientCommand.Flag("verify-ip", "").Hidden().PlaceHolder("SAN").IPList()
	clientAllowedURIs    = clientCommand.Flag("verify-uri", "Allow servers with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
	clientVerifySpkiPin  = clientCommand.Flag("verify-spki-pin", "Verify the server matches the given SPKI pin of the form <algo>:<base64-digest> (repeatable, e.g. sha256:...). This is out-of-band key pinning: the server is authenticated by the pin alone. Its certificate chain, validity period, and hostname are not verified. Mutually exclusive with other verification flags.").PlaceHolder("PIN").Strings()
	clientAllowPolicy    = clientCommand.Flag("verify-policy", "Allow passing the location of an OPA bundle.").PlaceHolder("BUNDLE").String()
	clientAllowQuery     = clientCommand.Flag("verify-query", "Rego query to evaluate against the server certificate and the policy.").PlaceHolder("QUERY").String()
	clientDisableAuth    = clientCommand.Flag("disable-authentication", "Disable client authentication, no certificate will be provided to the server.").Default("false").Bool()

	// TLS options
	keystorePath       = app.Flag("keystore", "Path to keystore (combined PEM with cert/key, or PKCS12 keystore).").PlaceHolder("PATH").Envar("KEYSTORE_PATH").String()
	certPath           = app.Flag("cert", "Path to certificate (PEM with certificate chain).").PlaceHolder("PATH").Envar("CERT_PATH").String()
	keyPath            = app.Flag("key", "Path to certificate private key (PEM with private key).").PlaceHolder("PATH").Envar("KEY_PATH").String()
	keystorePass       = app.Flag("storepass", "Password for keystore (PKCS#12 or JCEKS; optional for PKCS#12).").PlaceHolder("PASS").Envar("KEYSTORE_PASS").String()
	caBundlePath       = app.Flag("cacert", "Path to CA bundle file (PEM/X509). Uses system trust store by default.").Envar("CACERT_PATH").String()
	useWorkloadAPI        = app.Flag("use-workload-api", "If true, certificate and root CAs are retrieved via the SPIFFE Workload API").Bool()
	useWorkloadAPIAddr    = app.Flag("use-workload-api-addr", "If set, certificates and root CAs are retrieved via the SPIFFE Workload API at the specified address (implies --use-workload-api)").Envar("SPIFFE_ENDPOINT_SOCKET").PlaceHolder("ADDR").String()
	useWorkloadAPITimeout = app.Flag("use-workload-api-timeout", "Timeout for the initial certificate fetch from the SPIFFE Workload API at startup (set to 0 to wait indefinitely)").Default("10m").Duration()

	// Deprecated cipher suite flags
	enabledCipherSuites     = app.Flag("cipher-suites", "Set of cipher suites to enable, comma-separated, in order of preference (AES, CHACHA).").Hidden().Default("AES,CHACHA").String()
	allowUnsafeCipherSuites = app.Flag("allow-unsafe-cipher-suites", "Allow cipher suites deemed to be unsafe to be enabled via the cipher-suites flag.").Hidden().Default("false").Bool()
	maxTLSVersion           = app.Flag("max-tls-version", "Maximum SSL/TLS version to use (TLS1.2, TLS1.3). If unset, uses the Go default.").Default("").Hidden().String()

	// Reloading and timeouts
	timedReload            = app.Flag("timed-reload", "Reload keystores every given interval (e.g. 300s), refresh listener/client on changes.").PlaceHolder("DURATION").Duration()
	processShutdownTimeout = app.Flag("shutdown-timeout", "Process shutdown timeout. Terminates after timeout even if connections still open.").Default("5m").Duration()
	connectTimeout         = app.Flag("connect-timeout", "Timeout for establishing connections, handshakes.").Default("10s").Duration()
	closeTimeout           = app.Flag("close-timeout", "Timeout for closing connections when one side terminates. Zero means immediate closure.").Default("60s").Duration()
	maxConnLifetime        = app.Flag("max-conn-lifetime", "Maximum lifetime for connections post handshake, no matter what. Zero means infinite.").Default("0s").Duration()
	maxConcurrentConns     = app.Flag("max-concurrent-conns", "Maximum number of concurrent connections to handle in the proxy. Zero means infinite.").Default("0").Uint32()

	// Metrics options
	metricsGraphite = app.Flag("metrics-graphite", "Collect metrics and report them to the given graphite instance (raw TCP).").PlaceHolder("ADDR").TCP()
	metricsURL      = app.Flag("metrics-url", "Collect metrics and POST them periodically to the given URL (via HTTP/JSON).").PlaceHolder("URL").String()
	metricsPrefix   = app.Flag("metrics-prefix", fmt.Sprintf("Set prefix string for all reported metrics (default: %s).", defaultMetricsPrefix)).PlaceHolder("PREFIX").Default(defaultMetricsPrefix).String()
	metricsInterval = app.Flag("metrics-interval", "Collect (and post/send) metrics every specified interval.").Default("30s").Duration()

	// Status, logging & other
	statusAddress  = app.Flag("status", "Enable serving /_status and /_metrics on given [http(s)://]HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME.").PlaceHolder("ADDR").String()
	enableProf     = app.Flag("enable-pprof", "Enable serving /debug/pprof endpoints alongside /_status (for profiling).").Bool()
	enableShutdown = app.Flag("enable-shutdown", "Enable serving a /_shutdown endpoint alongside /_status to allow terminating via HTTP POST request.").Default("false").Bool()
	quiet          = app.Flag("quiet", "Silence log messages (can be all, conns, conn-errs, handshake-errs; repeat flag for more than one)").Default("").Enums("", "all", "conns", "handshake-errs", "conn-errs")
	skipResolve    = app.Flag("skip-resolve", "Skip resolving target host on startup (useful to start Ghostunnel before network is up).").Default("false").Bool()

	// Man page /help
	_ = app.Flag("help-custom-man", "Generate a man page.").Hidden().PreAction(generateManPage).Bool()
)

func init() {
	// Optional keychain identity flag, if compiled for a supported platform
	if certloader.SupportsKeychain() {
		keychainIdentity = app.Flag("keychain-identity", "Use local keychain identity with given serial/common name (instead of keystore file).").PlaceHolder("CN").String()
		keychainIssuer = app.Flag("keychain-issuer", "Use local keychain identity with given issuer name (instead of keystore file).").PlaceHolder("CN").String()
		if runtime.GOOS == "darwin" {
			keychainRequireToken = app.Flag("keychain-require-token", "Require keychain identity to be from a physical token (sets 'access group' to 'token', macOS only).").Bool()
		} else {
			// The "require token" flag doesn't do anything on Windows/Linux, so we hide it.
			isFalse := false
			keychainRequireToken = &isFalse
		}
	}

	// Optional PKCS#11 flags, if compiled with CGO enabled
	if certloader.SupportsPKCS11() {
		pkcs11Module = app.Flag("pkcs11-module", "Path to PKCS11 module (SO) file (optional).").Envar("PKCS11_MODULE").PlaceHolder("PATH").ExistingFile()
		pkcs11TokenLabel = app.Flag("pkcs11-token-label", "Token label for slot/key in PKCS11 module (optional).").Envar("PKCS11_TOKEN_LABEL").PlaceHolder("LABEL").String()
		pkcs11PIN = app.Flag("pkcs11-pin", "PIN code for slot/key in PKCS11 module (optional).").Envar("PKCS11_PIN").PlaceHolder("PIN").String()
	}

	if runtime.GOOS == "linux" {
		// Deprecated flag: Landlock is now enabled by default.
		app.Flag("use-landlock", "").Hidden().Bool()

		// Flag to disable use of landlock if necessary. Note that landlock is automatically disabled when PKCS#11 is used.
		disableLandlock = app.Flag("disable-landlock", "Disable the best-effort landlock sandboxing.").Bool()
	}

	// Aliases for flags that were renamed to be backwards-compatible
	serverCommand.Flag("allow-dns-san", "").Hidden().StringsVar(serverAllowedDNSs)
	serverCommand.Flag("allow-ip-san", "").Hidden().IPListVar(serverAllowedIPs)
	serverCommand.Flag("allow-uri-san", "").Hidden().StringsVar(serverAllowedURIs)
	clientCommand.Flag("verify-dns-san", "").Hidden().StringsVar(clientAllowedDNSs)
	clientCommand.Flag("verify-ip-san", "").Hidden().IPListVar(clientAllowedIPs)
	clientCommand.Flag("verify-uri-san", "").Hidden().StringsVar(clientAllowedURIs)
	clientCommand.Flag("connect-proxy", "").Hidden().URLVar(clientProxy)

	// Register HTTP CONNECT proxy scheme for golang.org/x/net/proxy
	netproxy.RegisterDialerType("http", connectproxy.ConnectProxy)
}

// exitFunc is the single sanctioned reference to os.Exit; all process exits go
// through it so exit hooks can wrap it to flush coverage counters and so exits
// stay testable.
var exitFunc = os.Exit //nolint:forbidigo // the one allowed os.Exit indirection

// extraRWPaths collects additional filesystem paths that should be
// read-writable under landlock. Populated by init() hooks (e.g. the
// coverage build tag registers GOCOVERDIR here) and consumed by the
// linux landlock setup. Read/written only behind build tags, hence the
// nolint directive.
var extraRWPaths []string //nolint:unused

// Environment groups listening context data together.
type Environment struct {
	status          *statusHandler
	statusHTTP      *http.Server
	shutdownChannel chan bool
	shutdownTimeout time.Duration
	dial            proxy.DialFunc
	metrics         *sqmetrics.SquareMetrics
	proxyMetrics    *proxy.Metrics
	tlsConfigSource certloader.TLSConfigSource
	regoPolicy      policy.Policy
}

// Global logger instance
var logger = log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

func initLogger(systemLog bool, flags []string) (err error) {
	// If user has indicated request for system log (syslog on Unix, event
	// log on Windows), override default stdout logger with the platform
	// system logger instead. This can fail, e.g. in containers that don't
	// have syslog available.
	if slices.Contains(flags, "all") {
		// If --quiet=all if passed, disable all logging
		logger = log.New(io.Discard, "", 0)
		return
	}
	if systemLog {
		err = initSystemLogger()
	}
	return
}

// panicOnError panics if err is not nil
func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// Validate flags for both, server and client mode
func validateFlags(app *kingpin.Application) error {
	if *statusAddress == "" {
		if *enableProf {
			return fmt.Errorf("--enable-pprof requires --status to be set")
		}
		if *enableShutdown {
			return fmt.Errorf("--enable-shutdown requires --status to be set")
		}
	}
	if *metricsURL != "" && !strings.HasPrefix(*metricsURL, "http://") && !strings.HasPrefix(*metricsURL, "https://") {
		return fmt.Errorf("--metrics-url should start with http:// or https://")
	}
	if *serverStatusTargetAddress != "" && !strings.HasPrefix(*serverStatusTargetAddress, "http://") && !strings.HasPrefix(*serverStatusTargetAddress, "https://") {
		return fmt.Errorf("--target-status should start with http:// or https://")
	}
	if err := validateStatusAddress(); err != nil {
		return err
	}
	if *connectTimeout == 0 {
		return fmt.Errorf("--connect-timeout duration must not be zero")
	}
	if *useWorkloadAPITimeout < 0 {
		return fmt.Errorf("--use-workload-api-timeout duration must not be negative (use 0 to wait indefinitely)")
	}
	return nil
}

// validateStatusAddress enforces the supported shapes of --status: TLS may
// only be served on TCP, so the http:// and https:// scheme prefixes are
// rejected for unix/systemd/launchd listeners (which always serve plain HTTP).
func validateStatusAddress() error {
	if *statusAddress == "" {
		return nil
	}
	_, addr := socket.ParseHTTPAddress(*statusAddress)
	network, _, _, err := socket.ParseAddress(addr, true)
	if err != nil {
		return fmt.Errorf("invalid --status address: %w", err)
	}
	hasScheme := strings.HasPrefix(*statusAddress, "http://") || strings.HasPrefix(*statusAddress, "https://")
	if hasScheme && network != "tcp" {
		return fmt.Errorf("invalid --status network %q: http(s):// scheme requires a HOST:PORT target", network)
	}
	return nil
}

// Validates that addr is "safe" and does not need --unsafe-listen (or --unsafe-target).
func consideredSafe(addr string) bool {
	safePrefixes := []string{
		"unix:",
		"systemd:",
		"launchd:",
		"127.0.0.1:",
		"[::1]:",
		"localhost:",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
	}
	return false
}

func validateCredentials(creds []bool) int {
	count := 0
	for _, cred := range creds {
		if cred {
			count++
		}
	}
	return count
}

func validateCipherSuites() error {
	if _, err := resolveCipherSuites(*enabledCipherSuites, *allowUnsafeCipherSuites); err != nil {
		return err
	}
	return nil
}

func validateCertKeyPair() error {
	if (*keyPath != "" && *certPath == "") || (*certPath != "" && *keyPath == "" && !hasPKCS11()) {
		return errors.New("--cert/--key must be set together, unless using PKCS11 for private key")
	}
	return nil
}

func validateServerCredentials() error {
	count := validateCredentials([]bool{
		*keystorePath != "",
		hasKeychainIdentity(),
		(*certPath != "" && *keyPath != ""),
		(*certPath != "" && hasPKCS11()),
		*useWorkloadAPI,
		*serverAutoACMEFQDN != "",
	})
	if count == 0 {
		return errors.New("at least one of --keystore, --cert/--key, --auto-acme-cert, or --keychain-identity/issuer (if supported) flags is required")
	}
	if count > 1 {
		return errors.New("--keystore, --cert/--key, --auto-acme-cert, and --keychain-identity/issuer flags are mutually exclusive")
	}
	return validateCertKeyPair()
}

func validateServerAccessControl(hasAccessFlags, hasPinFlag, hasOPAFlags bool) error {
	if !(*serverDisableAuth) && !(*serverAllowAll) && !hasAccessFlags && !hasPinFlag && !hasOPAFlags {
		return errors.New("at least one access control flag (--allow-{all,cn,ou,dns,uri,spki-pin}, or OPA flags, or --disable-authentication) is required")
	}
	if !(*serverDisableAuth) && *serverAllowAll && (hasAccessFlags || hasPinFlag || hasOPAFlags) {
		return errors.New("--allow-all is mutually exclusive with other access control flags")
	}
	if *serverDisableAuth && (*serverAllowAll || hasAccessFlags || hasPinFlag || hasOPAFlags) {
		return errors.New("--disable-authentication is mutually exclusive with other access control flags")
	}
	if hasPinFlag && (hasAccessFlags || *serverAllowAll || hasOPAFlags) {
		return errors.New("--allow-spki-pin is mutually exclusive with other access control flags")
	}
	// The SPIFFE Workload API source independently disables normal verification
	// and wraps VerifyPeerCertificate, which would conflict with pin-only auth.
	if hasPinFlag && *useWorkloadAPI {
		return errors.New("--allow-spki-pin is mutually exclusive with --use-workload-api")
	}
	return nil
}

func validateServerTarget() error {
	if !*serverUnsafeTarget && !consideredSafe(*serverForwardAddress) {
		return errors.New("--target must be unix:PATH or localhost:PORT (unless --unsafe-target is set)")
	}
	network, _, _, err := socket.ParseAddress(*serverForwardAddress, true)
	if err != nil {
		return fmt.Errorf("invalid --target address: %w", err)
	}
	if !socket.IsDialableNetwork(network) {
		return fmt.Errorf("invalid --target network %q: only tcp and unix targets are supported (systemd:/launchd: cannot be dialed)", network)
	}
	return nil
}

func validateServerACME() error {
	if *serverAutoACMEFQDN == "" {
		return nil
	}
	if *serverAutoACMEEmail == "" {
		return errors.New("--auto-acme-cert was specified but no email address was provided with --auto-acme-email")
	}
	if !*serverAutoACMEAgreedTOS {
		return errors.New("--auto-acme-agree-to-tos was not specified and is required if --auto-acme-cert is specified")
	}
	return nil
}

func validateServerOPA(hasOPAFlags bool) error {
	if !hasOPAFlags {
		return nil
	}
	if *serverAllowPolicy == "" || *serverAllowQuery == "" {
		return errors.New("--allow-policy and --allow-query have to be used together")
	}
	return nil
}

// Decoded SPKI pins, populated by decodeSPKIPins during flag validation from
// --allow-spki-pin / --verify-spki-pin so that malformed pins are rejected at
// startup rather than at listen/dial time.
var (
	decodedServerPins []auth.SPKIPin
	decodedClientPins []auth.SPKIPin
)

// decodeSPKIPins parses SPKI pin flag values, tagging any parse error with the
// flag name so the message is actionable. Used by both the server
// (--allow-spki-pin) and client (--verify-spki-pin) validators.
func decodeSPKIPins(values []string, flag string) ([]auth.SPKIPin, error) {
	pins, err := auth.ParseSPKIPins(values)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", flag, err)
	}
	return pins, nil
}

// Validate flags for server mode
func serverValidateFlags() error {
	if err := validateServerCredentials(); err != nil {
		return err
	}

	hasAccessFlags := len(*serverAllowedCNs) > 0 ||
		len(*serverAllowedOUs) > 0 ||
		len(*serverAllowedDNSs) > 0 ||
		len(*serverAllowedIPs) > 0 ||
		len(*serverAllowedURIs) > 0
	hasPinFlag := len(*serverAllowSpkiPin) > 0
	hasOPAFlags := len(*serverAllowPolicy) > 0 || len(*serverAllowQuery) > 0

	if err := validateServerAccessControl(hasAccessFlags, hasPinFlag, hasOPAFlags); err != nil {
		return err
	}
	if err := validateServerPin(); err != nil {
		return err
	}
	if err := validateServerTarget(); err != nil {
		return err
	}
	if err := validateServerACME(); err != nil {
		return err
	}
	if err := validateServerOPA(hasOPAFlags); err != nil {
		return err
	}
	if err := validateServerProxyProtocol(); err != nil {
		return err
	}
	return validateCipherSuites()
}

// validateServerPin decodes --allow-spki-pin into decodedServerPins.
func validateServerPin() error {
	// Reset decodedServerPins first so repeated in-process validation (as unit
	// tests do) can't leak a previous run's decoded pins into a later run that
	// omits the flag or fails parsing.
	decodedServerPins = nil
	if len(*serverAllowSpkiPin) == 0 {
		return nil
	}
	pins, err := decodeSPKIPins(*serverAllowSpkiPin, "--allow-spki-pin")
	if err != nil {
		return err
	}
	decodedServerPins = pins
	return nil
}

func validateServerProxyProtocol() error {
	if *serverProxyProtocol && *serverProxyProtocolMode != "" {
		return errors.New("--proxy-protocol and --proxy-protocol-mode are mutually exclusive")
	}
	return nil
}

func validateClientCredentials() error {
	// --disable-authentication is mutex with file-based identity flags, but
	// may be combined with --use-workload-api for server verification only.
	disableAuthCounts := *clientDisableAuth && !*useWorkloadAPI
	count := validateCredentials([]bool{
		*keystorePath != "",
		hasKeychainIdentity(),
		(*certPath != "" && *keyPath != ""),
		(*certPath != "" && hasPKCS11()),
		*useWorkloadAPI,
		disableAuthCounts,
	})
	if count == 0 {
		return errors.New("at least one of --keystore, --cert/--key, --keychain-identity/issuer (if supported), --use-workload-api or --disable-authentication flags is required")
	}
	if count > 1 {
		return errors.New("--keystore, --cert/--key, --keychain-identity/issuer, --use-workload-api and --disable-authentication flags are mutually exclusive")
	}
	return validateCertKeyPair()
}

func validateClientListen() error {
	if !*clientUnsafeListen && !consideredSafe(*clientListenAddress) {
		return fmt.Errorf("--listen must be unix:PATH, localhost:PORT, systemd:NAME or launchd:NAME (unless --unsafe-listen is set)")
	}
	return nil
}

func validateClientTarget() error {
	network, _, _, err := socket.ParseAddress(*clientForwardAddress, true)
	if err != nil {
		return fmt.Errorf("invalid --target address: %w", err)
	}
	if network != "tcp" {
		return fmt.Errorf("invalid --target network %q: client mode requires a HOST:PORT TCP target", network)
	}
	return nil
}

func validateClientOPA() error {
	hasOPAFlags := len(*clientAllowPolicy) > 0 || len(*clientAllowQuery) > 0
	if !hasOPAFlags {
		return nil
	}
	if *clientAllowPolicy == "" || *clientAllowQuery == "" {
		return errors.New("--verify-policy and --verify-query have to be used together")
	}
	return nil
}

// validateClientPin decodes --verify-spki-pin into decodedClientPins.
func validateClientPin() error {
	// Reset decodedClientPins first so repeated in-process validation (as
	// unit tests do) can't leak a previous run's decoded pins into a later run
	// that omits the flag or fails parsing.
	decodedClientPins = nil
	if len(*clientVerifySpkiPin) == 0 {
		return nil
	}
	// The SPIFFE Workload API source independently disables normal verification
	// and wraps VerifyPeerCertificate, which would conflict with pin-only auth.
	if *useWorkloadAPI {
		return errors.New("--verify-spki-pin is mutually exclusive with --use-workload-api")
	}
	hasVerifyFlags := len(*clientAllowedCNs) > 0 ||
		len(*clientAllowedOUs) > 0 ||
		len(*clientAllowedDNSs) > 0 ||
		len(*clientAllowedIPs) > 0 ||
		len(*clientAllowedURIs) > 0
	hasOPAFlags := len(*clientAllowPolicy) > 0 || len(*clientAllowQuery) > 0
	// --disable-authentication is deliberately NOT a conflict here: on the client
	// it only governs whether we present our own certificate to the server, not
	// how we verify the server.
	if hasVerifyFlags || hasOPAFlags {
		return errors.New("--verify-spki-pin is mutually exclusive with other verification flags")
	}
	pins, err := decodeSPKIPins(*clientVerifySpkiPin, "--verify-spki-pin")
	if err != nil {
		return err
	}
	decodedClientPins = pins
	return nil
}

// Validate flags for client mode
func clientValidateFlags() error {
	if err := validateClientCredentials(); err != nil {
		return err
	}
	if err := validateClientListen(); err != nil {
		return err
	}
	if err := validateClientTarget(); err != nil {
		return err
	}
	if err := validateClientOPA(); err != nil {
		return err
	}
	if err := validateClientPin(); err != nil {
		return err
	}
	return validateCipherSuites()
}

// serverProxyProtoMode computes the ProxyProtocolMode from the
// --proxy-protocol and --proxy-protocol-mode flags.
func serverProxyProtoMode() proxy.ProxyProtocolMode {
	if *serverProxyProtocolMode != "" {
		switch *serverProxyProtocolMode {
		case "tls":
			return proxy.ProxyProtocolTLS
		case "tls-full":
			return proxy.ProxyProtocolTLSFull
		default:
			return proxy.ProxyProtocolConn
		}
	}
	if *serverProxyProtocol {
		return proxy.ProxyProtocolConn
	}
	return proxy.ProxyProtocolOff
}

func main() {
	if isRunningAsService() {
		runAsService()
		return
	}
	err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		exitFunc(1)
	}
	exitFunc(0)
}

// applyFlagImplications applies implicit flag relationships after parsing.
// Setting --use-workload-api-addr implies --use-workload-api.
func applyFlagImplications() {
	if *useWorkloadAPIAddr != "" {
		*useWorkloadAPI = true
	}
}

func run(args []string) error {
	app.Version(fmt.Sprintf("rev %s built with %s (pkcs11: %v, keychain: %v)", version, runtime.Version(), certloader.SupportsPKCS11(), certloader.SupportsKeychain()))
	app.Validate(validateFlags)
	app.UsageTemplate(kingpin.LongHelpTemplate)

	command, parseErr := app.Parse(args)
	command = kingpin.MustParse(command, parseErr)

	if handled, err := runServiceCommand(command); handled {
		return err
	}

	applyFlagImplications()

	// Logger
	err := initLogger(useSystemLog(), *quiet)
	if err != nil {
		return fmt.Errorf("unable to set up logger: %w", err)
	}

	logger.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
	logger.Printf("starting ghostunnel in %s mode", command)

	// Landlock
	pkcs11Enabled := pkcs11Module != nil && *pkcs11Module != ""
	hasLandlock := runtime.GOOS == "linux" && !*disableLandlock

	if pkcs11Enabled && hasLandlock {
		logger.Printf("note: using pkcs11, skipping landlock setup (landlock is not compatible with pkcs11)")
	}
	if !pkcs11Enabled && hasLandlock {
		logger.Printf("setting up landlock rules to limit process privileges")

		// Continue even if landlock errs out. Landlock is a new-ish feature and
		// not supported on older kernels (net rules were added in v6.7, Jan 2024).
		// We may change this in a future version of Ghostunnel as we get more
		// comfortable with Landlock.
		err := setupLandlock()
		if err != nil {
			logger.Printf("warning: unable to set up landlock: %v", err)
		}
	}

	// Metrics
	//
	// Metrics leave the process through exactly three sinks: the pull surface
	// (/_metrics*, served only when --status is set) and the two push reporters
	// (--metrics-graphite, --metrics-url). When none is configured, nothing can
	// observe the registry, so we skip metrics collection entirely: the proxy
	// gets no-op handles (see proxy.NilMetrics) and neither metrics background
	// goroutine is started.
	//
	// NOTE: these flags are start-time-only; nothing reconfigures them at
	// runtime (cert hot-reload does not touch them), so this predicate is
	// decided once here and stays valid for the process lifetime. If that ever
	// changes, this gate must be re-evaluated.
	metricsConsumed := *statusAddress != "" || *metricsGraphite != nil || *metricsURL != ""

	// proxyMetrics drives the connection hot path: live handles on the default
	// registry when metrics are consumed, no-op handles otherwise.
	var proxyMetrics *proxy.Metrics
	if metricsConsumed {
		proxyMetrics = proxy.LiveMetrics(metrics.DefaultRegistry)
	} else {
		proxyMetrics = proxy.NilMetrics()
	}

	// metricsSink is the sq-metrics collector; left nil when metrics are not
	// consumed (its only readers live in serveStatus, which is not registered
	// unless --status is set, in which case metrics are consumed).
	var metricsSink *sqmetrics.SquareMetrics
	if metricsConsumed {
		if *metricsGraphite != nil {
			logger.Printf("metrics enabled; reporting metrics via TCP to %s", *metricsGraphite)
			go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *metricsGraphite)
		}
		if *metricsURL != "" {
			logger.Printf("metrics enabled; reporting metrics via POST to %s", *metricsURL)
		}

		// Bridge go-metrics into the prometheus registry for /_metrics/prometheus.
		// The overhead is minimal (an in-mem map is updated with the values).
		pClient := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, *metricsPrefix, "", prometheus.DefaultRegisterer, 1*time.Second)
		go pClient.UpdatePrometheusMetrics()

		// Read CA bundle for passing to metrics library
		ca, err := certloader.LoadTrustStore(*caBundlePath)
		if err != nil {
			logger.Printf("error: unable to build TLS config: %s\n", err)
			return err
		}

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    ca,
				},
			},
		}
		metricsSink = sqmetrics.NewMetrics(*metricsURL, *metricsPrefix, client, *metricsInterval, metrics.DefaultRegistry, logger)
	}

	switch command {
	case serverCommand.FullCommand():
		if err := serverValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		// Duplicating this call to getTLSConfigSource() in all switch cases
		// because we need to complete the validation of the command flags first.
		tlsConfigSource, err := getTLSConfigSource(*serverDisableAuth)
		if err != nil {
			return err
		}

		dial, err := serverBackendDialer()
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *serverForwardAddress)

		// Compile the rego policy before constructing the Environment so the
		// reload goroutine (started below) does not race with a later
		// assignment to env.regoPolicy.
		regoPolicy, err := loadOPAPolicy(*serverAllowPolicy, *serverAllowQuery)
		if err != nil {
			return err
		}

		status := newStatusHandler(dial, command, *serverListenAddress, *serverForwardAddress, *serverStatusTargetAddress)
		env := &Environment{
			status:          status,
			shutdownChannel: make(chan bool, 1),
			shutdownTimeout: *processShutdownTimeout,
			dial:            dial,
			metrics:         metricsSink,
			proxyMetrics:    proxyMetrics,
			tlsConfigSource: tlsConfigSource,
			regoPolicy:      regoPolicy,
		}
		go env.reloadHandler(*timedReload)

		// Start listening
		err = serverListen(env, regoPolicy)
		if err != nil {
			logger.Printf("error from server listen: %s\n", err)
		}
		return err

	case clientCommand.FullCommand():
		if err := clientValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		// Duplicating this call to getTLSConfigSource() in all switch cases
		// because we need to complete the validation of the command flags first.
		tlsConfigSource, err := getTLSConfigSource(*clientDisableAuth)
		if err != nil {
			return err
		}

		// Note: A target address given on the command line may not be resolvable
		// on our side if the connection is forwarded through a CONNECT proxy. Hence,
		// we ignore "no such host" errors when a proxy is set and trust that the
		// proxy will be able to find the target for us.
		skipRes := *skipResolve || *clientProxy != nil
		network, address, host, err := socket.ParseAddress(*clientForwardAddress, skipRes)
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *clientForwardAddress)

		dial, policy, err := clientBackendDialer(tlsConfigSource, network, address, host)
		if err != nil {
			logger.Printf("error: unable to build dialer: %s\n", err)
			return err
		}

		// NOTE: We don't provide a target status address here because this handler
		// is for the client /_status endpoint, its target will be a Ghostunnel in
		// server mode, and thus this should be a (default) TCP check.
		status := newStatusHandler(dial, command, *clientListenAddress, *clientForwardAddress, "")
		env := &Environment{
			status:          status,
			shutdownChannel: make(chan bool, 1),
			shutdownTimeout: *processShutdownTimeout,
			dial:            dial,
			metrics:         metricsSink,
			proxyMetrics:    proxyMetrics,
			tlsConfigSource: tlsConfigSource,
			regoPolicy:      policy,
		}
		go env.reloadHandler(*timedReload)

		// Start listening
		err = clientListen(env)
		if err != nil {
			logger.Printf("error from client listen: %s\n", err)
		}
		return err
	}

	return errors.New("unknown command")
}

// loadOPAPolicy compiles a rego policy from the given path+query. Returns
// (nil, nil) when either flag is empty (OPA disabled); otherwise loads the
// policy and returns it, or an error if compilation fails.
func loadOPAPolicy(allowPolicy, allowQuery string) (policy.Policy, error) {
	if len(allowPolicy) == 0 || len(allowQuery) == 0 {
		return nil, nil
	}
	p, err := policy.LoadFromPath(allowPolicy, allowQuery)
	if err != nil {
		logger.Printf("Invalid rego policy or query: %s", err)
		return nil, err
	}
	return p, nil
}

// Open listening socket in server mode. Take note that we create a
// "reusable port listener", meaning we pass SO_REUSEPORT to the kernel. This
// allows us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purpose of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is expiring.
func serverListen(env *Environment, regoPolicy policy.Policy) error {
	config, err := buildServerConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites)
	if err != nil {
		logger.Printf("error trying to read CA bundle: %s", err)
		return err
	}

	allowedURIs, err := wildcard.CompileList(*serverAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --allow-uri flag (%s)", err)
		return err
	}

	serverACL := auth.ACL{
		AllowAll:        *serverAllowAll,
		AllowedCNs:      *serverAllowedCNs,
		AllowedOUs:      *serverAllowedOUs,
		AllowedDNSs:     *serverAllowedDNSs,
		AllowedIPs:      *serverAllowedIPs,
		AllowOPAQuery:   regoPolicy,
		AllowedURIs:     allowedURIs,
		OPAQueryTimeout: *connectTimeout,
		AllowedPins:     decodedServerPins,
	}

	if *serverDisableAuth {
		config.ClientAuth = tls.NoClientCert
	} else {
		if serverACL.PinningEnabled() {
			// SPKIPin-based verification: require a client cert but skip chain
			// validation. The ACL callback verifies the SPKI hash instead.
			config.ClientAuth = tls.RequireAnyClientCert
		}
		config.VerifyPeerCertificate = serverACL.VerifyPeerCertificateServer
	}

	listener, err := socket.ParseAndOpen(*serverListenAddress)
	if err != nil {
		logger.Printf("error trying to listen: %s", err)
		return err
	}

	serverConfig, err := getServerConfig(env.tlsConfigSource, config)
	if err != nil {
		listener.Close()
		logger.Printf("error: unable to get server TLS config: %s", err)
		return err
	}

	p := proxy.New(
		certloader.NewListener(listener, serverConfig),
		*connectTimeout,
		*closeTimeout,
		*maxConnLifetime,
		int64(*maxConcurrentConns),
		env.dial,
		logger,
		proxyLoggerFlags(*quiet),
		serverProxyProtoMode(),
		env.proxyMetrics,
	)

	if *statusAddress != "" {
		err := env.serveStatus()
		if err != nil {
			listener.Close()
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *serverListenAddress)

	go p.Accept()

	env.status.Listening()
	env.status.HandleWatchdog()
	env.signalHandler(p)
	p.Wait()

	return nil
}

// Open listening socket in client mode.
func clientListen(env *Environment) error {
	listener, err := socket.ParseAndOpen(*clientListenAddress)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		return err
	}

	p := proxy.New(
		listener,
		*connectTimeout,
		*closeTimeout,
		*maxConnLifetime,
		int64(*maxConcurrentConns),
		env.dial,
		logger,
		proxyLoggerFlags(*quiet),
		proxy.ProxyProtocolOff,
		env.proxyMetrics,
	)

	if *statusAddress != "" {
		err := env.serveStatus()
		if err != nil {
			listener.Close()
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *clientListenAddress)

	go p.Accept()

	env.status.Listening()
	env.status.HandleWatchdog()
	env.signalHandler(p)
	p.Wait()

	return nil
}

// shutdownHandler serves POST /_shutdown by signalling the shutdown channel.
// The send is non-blocking so repeated requests after shutdown has already
// been requested do not block the handler goroutine (which would stall
// graceful shutdown of the status HTTP server and leak goroutines until the
// shutdown timeout fires).
func (env *Environment) shutdownHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	logger.Printf("shutdown was requested via status endpoint")
	w.WriteHeader(http.StatusOK)

	// Non-blocking send: if a shutdown has already been requested (the
	// buffer is full or no reader is left), we drop this request rather
	// than block forever.
	select {
	case env.shutdownChannel <- true:
	default:
	}
}

// Serve /_status (if configured)
func (env *Environment) serveStatus() error {
	promHandler := promhttp.Handler()

	mux := http.NewServeMux()
	mux.Handle("/_status", env.status)
	mux.HandleFunc("/_metrics/json", func(w http.ResponseWriter, r *http.Request) {
		env.metrics.ServeHTTP(w, r)
	})
	mux.HandleFunc("/_metrics/prometheus", func(w http.ResponseWriter, r *http.Request) {
		promHandler.ServeHTTP(w, r)
	})
	mux.HandleFunc("/_metrics", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		format, ok := params["format"]
		if !ok || format[0] != "prometheus" {
			env.metrics.ServeHTTP(w, r)
			return
		}
		promHandler.ServeHTTP(w, r)
	})

	if *enableShutdown {
		mux.HandleFunc("/_shutdown", env.shutdownHandler)
	}

	if *enableProf {
		mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}

	https, addr := socket.ParseHTTPAddress(*statusAddress)

	network, address, _, err := socket.ParseAddress(addr, true)
	if err != nil {
		return err
	}

	listener, err := socket.Open(network, address)
	if err != nil {
		logger.Printf("error: unable to bind on status port: %s\n", err)
		return err
	}

	if network == "tcp" && https && env.tlsConfigSource.CanServe() {
		config, err := buildServerConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites)
		if err != nil {
			return err
		}
		config.ClientAuth = tls.NoClientCert

		serverConfig, err := getServerConfig(env.tlsConfigSource, config)
		if err != nil {
			return err
		}
		listener = certloader.NewListener(listener, serverConfig)
	}

	env.statusHTTP = &http.Server{
		Handler:           mux,
		ErrorLog:          logger,
		ReadHeaderTimeout: *connectTimeout,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		err := env.statusHTTP.Serve(listener)
		if err != nil {
			logger.Printf("error serving status port: %s", err)
		}
	}()

	return nil
}

// Get backend dialer function in server mode (connecting to a unix socket or tcp port)
func serverBackendDialer() (proxy.DialFunc, error) {
	backendNet, backendAddr, _, err := socket.ParseAddress(*serverForwardAddress, *skipResolve)
	if err != nil {
		return nil, err
	}

	return func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: *connectTimeout}
		return d.DialContext(ctx, backendNet, backendAddr)
	}, nil
}

// Get backend dialer function in client mode (connecting to a TLS port)
func clientBackendDialer(
	tlsConfigSource certloader.TLSConfigSource,
	network, address, host string,
) (proxy.DialFunc, policy.Policy, error) {

	config, err := buildClientConfig(*enabledCipherSuites, *maxTLSVersion, *allowUnsafeCipherSuites)
	if err != nil {
		return nil, nil, err
	}

	if *clientServerName == "" {
		config.ServerName = host
	} else {
		config.ServerName = *clientServerName
	}

	allowedURIs, err := wildcard.CompileList(*clientAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --verify-uri flag (%s)", err)
		return nil, nil, err
	}

	regoPolicy, err := loadOPAPolicy(*clientAllowPolicy, *clientAllowQuery)
	if err != nil {
		return nil, nil, err
	}

	clientACL := auth.ACL{
		AllowedCNs:      *clientAllowedCNs,
		AllowedOUs:      *clientAllowedOUs,
		AllowedDNSs:     *clientAllowedDNSs,
		AllowedIPs:      *clientAllowedIPs,
		AllowedURIs:     allowedURIs,
		AllowOPAQuery:   regoPolicy,
		OPAQueryTimeout: *connectTimeout,
		AllowedPins:     decodedClientPins,
	}

	if clientACL.PinningEnabled() {
		// SPKIPin-based verification: skip chain and hostname validation.
		// The ACL callback will verify the SPKI hash.
		config.InsecureSkipVerify = true
	}

	config.VerifyPeerCertificate = clientACL.VerifyPeerCertificateClient

	var dialer netproxy.ContextDialer = &net.Dialer{Timeout: *connectTimeout}

	if *clientProxy != nil {
		logger.Printf("using proxy %s", (*clientProxy).String())
		proxyDialer, err := netproxy.FromURL(*clientProxy, &net.Dialer{Timeout: *connectTimeout})
		if err != nil {
			logger.Printf("error: error configuring proxy: %s\n", err)
			return nil, nil, err
		}

		var ok bool
		dialer, ok = proxyDialer.(netproxy.ContextDialer)
		if !ok {
			logger.Printf("unexpected: proxy dialer scheme did not implement context dialing, aborting")
			return nil, nil, errors.New("unexpected: proxy dialer scheme did not implement context dialing, aborting")
		}
	}

	clientConfig, err := getClientConfig(tlsConfigSource, config)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get client TLS config: %w", err)
	}
	d := certloader.DialerWithCertificate(clientConfig, *connectTimeout, dialer)
	return func(ctx context.Context) (net.Conn, error) {
			return d.DialContext(ctx, network, address)
		},
		regoPolicy, nil
}

func proxyLoggerFlags(flags []string) int {
	out := proxy.LogEverything
	for _, flag := range flags {
		switch flag {
		case "all":
			// Disable all proxy logs
			out = 0
		case "conns":
			// Disable connection logs
			out = out & ^proxy.LogConnections
		case "conn-errs":
			// Disable connection errors logs
			out = out & ^proxy.LogConnectionErrors
		case "handshake-errs":
			// Disable handshake error logs
			out = out & ^proxy.LogHandshakeErrors
		}
	}
	return out
}

func getTLSConfigSource(disableAuth bool) (certloader.TLSConfigSource, error) {
	if *useWorkloadAPI {
		logger.Printf("using SPIFFE Workload API as certificate source")
		source, err := certloader.TLSConfigSourceFromWorkloadAPI(*useWorkloadAPIAddr, disableAuth, *useWorkloadAPITimeout, logger)
		if err != nil {
			logger.Printf("error: unable to create workload API TLS source: %s\n", err)
			return nil, err
		}
		return source, nil
	}

	if *serverAutoACMEFQDN != "" {
		logger.Printf("using ACME server as certificate source")
		acmeConfig := certloader.ACMEConfig{
			FQDN:               *serverAutoACMEFQDN,
			Email:              *serverAutoACMEEmail,
			TOSAgreed:          *serverAutoACMEAgreedTOS,
			ProdCAURL:          *serverAutoACMEProdCA,
			TestCAURL:          *serverAutoACMETestCA,
			CABundlePath:       *caBundlePath,
			RenewCheckInterval: *serverAutoACMERenewCheckInterval,
			AltTLSALPNPort:     *serverAutoACMEAltTLSALPNPort,
		}
		source, err := certloader.TLSConfigSourceFromACME(&acmeConfig)
		if err != nil {
			logger.Printf("error: Unable to load or obtain ACME cert: %s\n", err)
			return nil, err
		}
		return source, nil
	}

	cert, err := buildCertificate(*keystorePath, *certPath, *keyPath, *keystorePass, *caBundlePath, logger)
	if err != nil {
		logger.Printf("error: unable to load certificates: %s\n", err)
		return nil, err
	}
	return certloader.TLSConfigSourceFromCertificate(cert, logger), nil
}

func getServerConfig(source certloader.TLSConfigSource, config *tls.Config) (certloader.TLSServerConfig, error) {
	return source.GetServerConfig(config)
}

func getClientConfig(source certloader.TLSConfigSource, config *tls.Config) (certloader.TLSClientConfig, error) {
	return source.GetClientConfig(config)
}
