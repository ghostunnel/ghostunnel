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
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
)

var testRules = []landlock.Rule{}

type portRuleFunc = func(port uint16) landlock.NetRule

// addLandlockTestPaths can be used to add extra rules necessary for
// integration tests to run, e.g. the ability to write a coverage
// file to the current directory.
func addLandlockTestPaths(paths []string) {
	for _, path := range paths {
		testRules = append(testRules, landlock.RWDirs(path))
	}
}

// setupLandlock processes flags given to the process and generates an
// appropriate landlock rule configuration to limit our privileges.
func setupLandlock(logger *log.Logger) error {
	fsRules := []landlock.Rule{}
	fsRules = append(fsRules, testRules...)

	// Default net rules
	netRules := []landlock.Rule{
		// For DNS over TCP/53 (sometimes enabled for name resolution)
		landlock.ConnectTCP(uint16(53)),
	}

	// Default RW FS rules. Some paths we need always accessible for syslog and
	// for creating runtime/temporary files. Note that syslog can be in multiple
	// places not just /dev/log, e.g. /var/run is an option.
	for _, path := range []string{"/dev", "/var/run", "/tmp", "/proc"} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		fsRules = append(fsRules, landlock.RWDirs(path))
	}

	// Default RO FS rules. Some paths we need always accessible for name
	// resolution or time zones. For this purpose we keep /etc accessible. Note
	// that we could have chosen to limit ourselves to specific files (e.g.
	// /etc/nsswitch.conf, /etc/gai.conf), but it's difficult to enumerate the
	// exact set of files required in every conceivable situation.
	for _, path := range []string{"/etc", "/usr/share/zoneinfo"} {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		fsRules = append(fsRules, landlock.RODirs(path))
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

		rule, err := ruleFromStringAddress(*addr, landlock.BindTCP)
		if err != nil {
			logger.Printf("error processing argument '%s' for landlock rule", *addr)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	for _, addr := range []*string{
		serverForwardAddress,
		serverStatusTargetAddress,
		clientForwardAddress,
		useWorkloadAPIAddr,
		metricsURL,
	} {
		if addr == nil || len(*addr) == 0 {
			continue
		}

		rule, err := ruleFromStringAddress(*addr, landlock.ConnectTCP)
		if err != nil {
			logger.Printf("error processing argument '%s' for landlock rule", *addr)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	// Process string flags containing file paths. Since we need to able to
	// reload these files even after the file was changed/rewritten, we need to
	// add a RO rule on the entire parent directory.
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
		if _, err := os.Stat(*path); errors.Is(err, os.ErrNotExist) {
			continue
		}

		// Note: If one of these args is a symlink, we also need to add a rule for
		// the target of the symlink.
		fsRules = append(fsRules, landlock.RODirs(filepath.Dir(*path)))

		target, err := filepath.EvalSymlinks(*path)
		if err != nil {
			continue
		}
		if target != *path {
			fsRules = append(fsRules, landlock.RODirs(filepath.Dir(target)))
		}
	}

	// Process net.TCPAddr flags.
	for _, addr := range []**net.TCPAddr{metricsGraphite} {
		if addr == nil || *addr == nil {
			continue
		}

		rule, err := ruleFromTCPAddress(*addr, landlock.ConnectTCP)
		if err != nil {
			logger.Printf("error processing argument '%s' for landlock rule", *addr)
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
			logger.Printf("error processing argument '%s' for landlock rule", *url)
		}
		if rule != nil {
			netRules = append(netRules, rule)
		}
	}

	// Print landlock errors, but continue running. Landlock is a relatively new
	// feature and not supported on older kernels (net rules were added in v6.7,
	// Jan 2024). We may change this in a future version of Ghostunnel as we get
	// more comfortable with Landlock.
	config := landlock.V4
	err := config.RestrictPaths(fsRules...)
	if err != nil {
		logger.Printf("warning: unable to set up landlock filesystem rules: %v", err)
		return err
	}
	err = config.RestrictNet(netRules...)
	if err != nil {
		logger.Printf("warning: unable to set up landlock network rules: %v", err)
	}
	return err
}

func ruleFromStringAddress(addr string, ruleFromPort portRuleFunc) (landlock.Rule, error) {
	if strings.HasPrefix(addr, "unix:") {
		return landlock.RWFiles(addr[5:]), nil
	}
	if strings.HasPrefix(addr, "systemd:") || strings.HasPrefix(addr, "launchd:") {
		// Socket activation - no rule needed
		return nil, nil
	}
	if strings.HasPrefix(addr, "http://") || strings.HasPrefix(addr, "https://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		return ruleFromURL(u, ruleFromPort)
	}
	parts := strings.Split(addr, ":")
	if len(parts) < 2 {
		return nil, errors.New("unable to extract port number from address")
	}
	port, err := strconv.ParseUint(parts[len(parts)-1], 10, 16)
	if err != nil {
		return nil, errors.New("unable to extract port number from address")
	}
	if port == 0 {
		return nil, errors.New("unable to extract port number from address")
	}
	return ruleFromPort(uint16(port)), nil
}

func ruleFromTCPAddress(addr *net.TCPAddr, ruleFromPort portRuleFunc) (landlock.Rule, error) {
	if addr.Port == 0 {
		return nil, errors.New("unable to extract port number from address")
	}
	return ruleFromPort(uint16(addr.Port)), nil
}

func ruleFromURL(u *url.URL, ruleFromPort portRuleFunc) (landlock.Rule, error) {
	port := u.Port()
	if len(port) == 0 {
		if u.Scheme == "http" {
			return ruleFromPort(uint16(80)), nil
		}
		if u.Scheme == "https" {
			return ruleFromPort(uint16(443)), nil
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
