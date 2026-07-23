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
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/certloader"
	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/stretchr/testify/assert"
	netproxy "golang.org/x/net/proxy"
)

func TestInitLoggerQuiet(t *testing.T) {
	originalLogger := logger
	err := initLogger(false, []string{"all"})
	assert.Nil(t, err)

	updatedLogger := logger
	assert.NotEqual(t, originalLogger, updatedLogger, "should have updated logger object")
	assert.NotNil(t, logger, "logger should never be nil after init")
}

func TestInitLoggerSystemLog(t *testing.T) {
	originalLogger := logger
	defer func() { logger = originalLogger }()

	err := initLogger(true, []string{})
	if err != nil {
		// Tests running in containers often don't have access to syslog,
		// so we can't depend on syslog being available for testing. If we
		// get an error from the syslog setup we just warn and skip test.
		t.Logf("System log not available for test, skipping: %s", err)
		assert.NotNil(t, logger, "logger should never be nil even after error")
		t.SkipNow()
		return
	}
	assert.NotEqual(t, originalLogger, logger, "should have updated logger object")
	assert.NotNil(t, logger, "logger should never be nil after init")
}

func TestPanicOnError(t *testing.T) {
	defer func() {
		if err := recover(); err == nil {
			t.Error("panicOnError should panic, but did not")
		}
	}()

	panicOnError(errors.New("error"))
}

func TestFlagValidation(t *testing.T) {
	// reset establishes a valid baseline so each case toggles exactly one thing.
	reset := func() {
		*enableProf = false
		*enableShutdown = false
		*statusAddress = ""
		*metricsURL = ""
		*serverStatusTargetAddress = ""
		*connectTimeout = 10 * time.Second
		*useWorkloadAPITimeout = 10 * time.Minute
	}
	defer reset()

	reset()
	*enableProf = true
	assert.NotNil(t, validateFlags(nil), "--enable-pprof implies --status")

	reset()
	*enableShutdown = true
	assert.NotNil(t, validateFlags(nil), "--enable-shutdown implies --status")

	reset()
	*metricsURL = "127.0.0.1"
	assert.NotNil(t, validateFlags(nil), "invalid --metrics-url should be rejected")

	reset()
	*serverStatusTargetAddress = "127.0.0.1:8000"
	assert.NotNil(t, validateFlags(nil), "--target-status should start with http:// or https://")

	reset()
	*connectTimeout = 0
	assert.NotNil(t, validateFlags(nil), "invalid --connect-timeout should be rejected")

	reset()
	*useWorkloadAPITimeout = -1
	assert.NotNil(t, validateFlags(nil), "negative --use-workload-api-timeout should be rejected")

	reset()
	*useWorkloadAPITimeout = 0
	assert.Nil(t, validateFlags(nil), "zero --use-workload-api-timeout (wait indefinitely) should be accepted")
}

func TestServerFlagValidation(t *testing.T) {
	// reset establishes a fully valid server config (keystore credential,
	// --allow-all, safe local target) so each case toggles exactly one thing.
	// Building each case from a known-good baseline avoids the trap where an
	// assertion passes for the wrong reason (e.g. failing credential validation
	// before ever reaching the access-control check it claims to exercise).
	reset := func() {
		*serverAllowAll = true
		*serverAllowedCNs = nil
		*serverAllowedOUs = nil
		*serverAllowedDNSs = nil
		*serverAllowedIPs = nil
		*serverAllowedURIs = nil
		*serverAllowPolicy = ""
		*serverAllowQuery = ""
		*serverAllowSpkiPin = nil
		*serverDisableAuth = false
		*useWorkloadAPI = false
		*keystorePath = "file"
		*certPath = ""
		*keyPath = ""
		keychainIdentity = nil
		keychainIssuer = nil
		*serverAutoACMEFQDN = ""
		*serverForwardAddress = "127.0.0.1:8080"
		*serverUnsafeTarget = false
		*serverProxyProtocol = false
		*serverProxyProtocolMode = ""
		*enabledCipherSuites = "AES,CHACHA"
		decodedServerPins = nil
	}
	defer reset()

	// Sanity: the baseline itself is valid.
	reset()
	assert.Nil(t, serverValidateFlags(), "baseline server config should be valid")

	// No access control mechanism at all is rejected.
	reset()
	*serverAllowAll = false
	assert.NotNil(t, serverValidateFlags(), "at least one access control flag is required")

	// --allow-all is mutually exclusive with every other access control flag.
	for name, set := range map[string]func(){
		"--allow-cn":  func() { *serverAllowedCNs = []string{"test"} },
		"--allow-ou":  func() { *serverAllowedOUs = []string{"test"} },
		"--allow-dns": func() { *serverAllowedDNSs = []string{"test"} },
		"--allow-ip":  func() { *serverAllowedIPs = []net.IP{net.IPv4(0, 0, 0, 0)} },
		"--allow-uri": func() { *serverAllowedURIs = []string{"spiffe://example.com/*"} },
	} {
		reset()
		set()
		assert.NotNil(t, serverValidateFlags(), "--allow-all is mutually exclusive with "+name)
	}

	// --allow-all is mutually exclusive with the OPA flags.
	reset()
	*serverAllowPolicy = "policy"
	*serverAllowQuery = "query"
	assert.NotNil(t, serverValidateFlags(), "--allow-all is mutually exclusive with OPA flags")

	// The OPA flags must be supplied together.
	reset()
	*serverAllowAll = false
	*serverAllowPolicy = "policy"
	assert.NotNil(t, serverValidateFlags(), "--allow-policy needs --allow-query")

	reset()
	*serverAllowAll = false
	*serverAllowQuery = "query"
	assert.NotNil(t, serverValidateFlags(), "--allow-query needs --allow-policy")

	// OPA flags MAY be combined with the --allow-* subject flags (they are
	// OR'd together at authorization time), on the server just as on the client.
	for name, set := range map[string]func(){
		"--allow-cn":  func() { *serverAllowedCNs = []string{"test"} },
		"--allow-ou":  func() { *serverAllowedOUs = []string{"test"} },
		"--allow-dns": func() { *serverAllowedDNSs = []string{"test"} },
		"--allow-ip":  func() { *serverAllowedIPs = []net.IP{net.IPv4(0, 0, 0, 0)} },
		"--allow-uri": func() { *serverAllowedURIs = []string{"spiffe://example.com/*"} },
	} {
		reset()
		*serverAllowAll = false
		*serverAllowPolicy = "policy"
		*serverAllowQuery = "query"
		set()
		assert.Nil(t, serverValidateFlags(), "OPA flags may be combined with "+name)
	}

	// --disable-authentication is a valid standalone access mode, but conflicts
	// with any other access control flag.
	reset()
	*serverAllowAll = false
	*serverDisableAuth = true
	assert.Nil(t, serverValidateFlags(), "--disable-authentication alone should be valid")

	reset()
	*serverDisableAuth = true // baseline still has --allow-all set
	assert.NotNil(t, serverValidateFlags(), "--disable-authentication is mutually exclusive with --allow-all")

	reset()
	*serverAllowAll = false
	*serverDisableAuth = true
	*serverAllowedCNs = []string{"test"}
	assert.NotNil(t, serverValidateFlags(), "--disable-authentication is mutually exclusive with --allow-cn")

	// Credential validation.
	reset()
	*keystorePath = ""
	err := serverValidateFlags()
	assert.NotNil(t, err, "at least one credential source is required")
	assert.Contains(t, err.Error(), "at least one of")

	reset()
	*keystorePath = ""
	*keyPath = "file"
	assert.NotNil(t, serverValidateFlags(), "--key without --cert should be rejected")

	reset()
	*keystorePath = ""
	*certPath = "file"
	assert.NotNil(t, serverValidateFlags(), "--cert without --key should be rejected")

	reset()
	*certPath = "file"
	*keyPath = "file"
	assert.NotNil(t, serverValidateFlags(), "--keystore and --cert/--key are mutually exclusive")

	reset()
	test := "test"
	keychainIdentity = &test
	assert.NotNil(t, serverValidateFlags(), "--keystore and --keychain-identity are mutually exclusive")

	reset()
	keychainIssuer = &test
	assert.NotNil(t, serverValidateFlags(), "--keystore and --keychain-issuer are mutually exclusive")

	// Target validation: non-local targets are rejected unless --unsafe-target.
	reset()
	*serverForwardAddress = "example.com:443"
	assert.NotNil(t, serverValidateFlags(), "should reject non-local address if --unsafe-target not set")

	// Cipher suite validation.
	reset()
	*enabledCipherSuites = "ABC"
	assert.NotNil(t, serverValidateFlags(), "invalid cipher suite option should be rejected")

	// PROXY protocol flags are mutually exclusive; either alone is fine.
	reset()
	*serverProxyProtocol = true
	*serverProxyProtocolMode = "tls"
	assert.NotNil(t, serverValidateFlags(), "--proxy-protocol and --proxy-protocol-mode are mutually exclusive")

	reset()
	*serverProxyProtocolMode = "tls"
	assert.Nil(t, serverValidateFlags(), "--proxy-protocol-mode alone should be valid")
}

func TestClientFlagValidation(t *testing.T) {
	// reset establishes a fully valid client config (keystore credential, safe
	// listen, valid target) so each case toggles exactly one thing.
	reset := func() {
		*keystorePath = "file"
		*certPath = ""
		*keyPath = ""
		keychainIdentity = nil
		keychainIssuer = nil
		*clientDisableAuth = false
		*useWorkloadAPI = false
		*clientUnsafeListen = false
		*clientListenAddress = "127.0.0.1:8080"
		*clientForwardAddress = "localhost:8443"
		*enabledCipherSuites = "AES,CHACHA"
		*clientAllowPolicy = ""
		*clientAllowQuery = ""
		*clientVerifySpkiPin = nil
		decodedClientPins = nil
	}
	defer reset()

	// Sanity: the baseline itself is valid.
	reset()
	assert.Nil(t, clientValidateFlags(), "baseline client config should be valid")

	reset()
	*clientListenAddress = "0.0.0.0:8080"
	assert.NotNil(t, clientValidateFlags(), "unsafe listen should be rejected")

	// Credential source is exactly one of keystore / cert-key / keychain /
	// disable-authentication.
	reset()
	*clientDisableAuth = true
	assert.NotNil(t, clientValidateFlags(), "--keystore can't be used with --disable-authentication")

	reset()
	*keystorePath = ""
	*certPath = "file"
	*keyPath = "file"
	*clientDisableAuth = true
	assert.NotNil(t, clientValidateFlags(), "--cert/--key can't be used with --disable-authentication")

	reset()
	*certPath = "file"
	*keyPath = "file"
	assert.NotNil(t, clientValidateFlags(), "--keystore can't be used with --cert/--key")

	reset()
	test := "test"
	keychainIdentity = &test
	assert.NotNil(t, clientValidateFlags(), "--keystore can't be used with --keychain-identity")

	reset()
	*keystorePath = ""
	assert.NotNil(t, clientValidateFlags(), "one of --keystore or --disable-authentication is required")

	reset()
	*keystorePath = ""
	*certPath = "file"
	assert.NotNil(t, clientValidateFlags(), "--cert without --key should be rejected")

	reset()
	*keystorePath = ""
	*keyPath = "file"
	assert.NotNil(t, clientValidateFlags(), "--key without --cert should be rejected")

	reset()
	*enabledCipherSuites = "ABC"
	assert.NotNil(t, clientValidateFlags(), "invalid cipher suite option should be rejected")

	// OPA flags must be used together, and either-neither is valid.
	reset()
	*clientAllowPolicy = "policy"
	assert.NotNil(t, clientValidateFlags(), "--verify-policy needs --verify-query")

	reset()
	*clientAllowQuery = "query"
	assert.NotNil(t, clientValidateFlags(), "--verify-query needs --verify-policy")

	reset()
	*clientAllowPolicy = "policy"
	*clientAllowQuery = "query"
	assert.Nil(t, clientValidateFlags(), "--verify-policy and --verify-query together should be valid")

	reset()
	assert.Nil(t, clientValidateFlags(), "neither OPA flag set should be valid")
}

func TestValidateServerAccessControlSpkiPin(t *testing.T) {
	reset := func() {
		*serverAllowAll = false
		*serverDisableAuth = false
		*useWorkloadAPI = false
	}
	defer reset()

	// --allow-spki-pin on its own is a valid access control mechanism.
	reset()
	assert.Nil(t, validateServerAccessControl(false, true, false), "--allow-spki-pin alone should be valid")

	// Combining --allow-spki-pin with any other mechanism is rejected. The
	// message varies by which branch fires (allow-all / disable-auth take
	// precedence), so we only assert that an error is returned.
	reset()
	assert.NotNil(t, validateServerAccessControl(true, true, false), "--allow-spki-pin and other --allow-* flags are mutually exclusive")

	reset()
	assert.NotNil(t, validateServerAccessControl(false, true, true), "--allow-spki-pin and OPA flags are mutually exclusive")

	reset()
	*serverAllowAll = true
	assert.NotNil(t, validateServerAccessControl(false, true, false), "--allow-spki-pin and --allow-all are mutually exclusive")

	reset()
	*serverDisableAuth = true
	assert.NotNil(t, validateServerAccessControl(false, true, false), "--allow-spki-pin and --disable-authentication are mutually exclusive")

	// --allow-spki-pin cannot be combined with the SPIFFE Workload API source.
	reset()
	*useWorkloadAPI = true
	err := validateServerAccessControl(false, true, false)
	if assert.NotNil(t, err, "--allow-spki-pin and --use-workload-api are mutually exclusive") {
		assert.Contains(t, err.Error(), "--use-workload-api")
	}

	// Sanity: with no mechanism at all, at least one flag is required.
	reset()
	assert.NotNil(t, validateServerAccessControl(false, false, false), "at least one access control flag is required")
}

func TestValidateServerSpkiPinParsing(t *testing.T) {
	validPin := "sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	// A minimally-valid server config so serverValidateFlags reaches the pin
	// decode/store path: file-based credentials, a safe target, and no other
	// access control flags (pin mode is mutually exclusive with them).
	reset := func() {
		*serverAllowSpkiPin = nil
		*certPath = "server.crt"
		*keyPath = "server.key"
		*keystorePath = ""
		*useWorkloadAPI = false
		*serverAutoACMEFQDN = ""
		*serverForwardAddress = "localhost:8080"
		*serverUnsafeTarget = false
		*serverAllowAll = false
		*serverDisableAuth = false
		*serverAllowedCNs = nil
		*serverAllowedOUs = nil
		*serverAllowedDNSs = nil
		*serverAllowedIPs = nil
		*serverAllowedURIs = nil
		*serverAllowPolicy = ""
		*serverAllowQuery = ""
		*serverProxyProtocol = false
		*serverProxyProtocolMode = ""
		decodedServerPins = nil
	}
	defer reset()

	// Valid pins are decoded and stored in decodedServerPins.
	reset()
	*serverAllowSpkiPin = []string{validPin, validPin}
	assert.Nil(t, serverValidateFlags(), "valid --allow-spki-pin should be accepted")
	assert.Equal(t, 2, len(decodedServerPins), "validation should decode the pins into decodedServerPins")

	// A malformed pin fails validation and leaves decodedServerPins nil.
	reset()
	*serverAllowSpkiPin = []string{"sha256:not valid base64 @@@"}
	err := serverValidateFlags()
	if assert.NotNil(t, err, "malformed --allow-spki-pin should be rejected at validation") {
		assert.Contains(t, err.Error(), "--allow-spki-pin", "error should name the offending flag")
	}
	assert.Nil(t, decodedServerPins, "no pins should be stored on validation failure")

	// A successful decode must not leak into a later in-process run that omits
	// --allow-spki-pin: validateServerPin resets decodedServerPins itself, so
	// this holds even without the test's own reset() clearing it.
	reset()
	*serverAllowSpkiPin = []string{validPin, validPin}
	assert.Nil(t, serverValidateFlags(), "valid --allow-spki-pin should be accepted")
	assert.Equal(t, 2, len(decodedServerPins))
	*serverAllowSpkiPin = nil
	*serverAllowAll = true
	assert.Nil(t, serverValidateFlags(), "baseline without --allow-spki-pin should be accepted")
	assert.Nil(t, decodedServerPins, "decodedServerPins from the earlier run should not leak into this one")
}

func TestValidateClientSpkiPin(t *testing.T) {
	validPin := "sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	reset := func() {
		*clientVerifySpkiPin = nil
		*clientAllowedCNs = nil
		*clientAllowedOUs = nil
		*clientAllowedDNSs = nil
		*clientAllowedIPs = nil
		*clientAllowedURIs = nil
		*clientAllowPolicy = ""
		*clientAllowQuery = ""
		*clientDisableAuth = false
		*useWorkloadAPI = false
		decodedClientPins = nil
	}
	defer reset()

	reset()
	assert.Nil(t, validateClientPin(), "no --verify-spki-pin should be valid")

	reset()
	*clientVerifySpkiPin = []string{validPin}
	assert.Nil(t, validateClientPin(), "--verify-spki-pin alone should be valid")

	reset()
	*clientVerifySpkiPin = []string{validPin, validPin}
	assert.Nil(t, validateClientPin(), "multiple --verify-spki-pin should be valid")
	assert.Equal(t, 2, len(decodedClientPins), "validation should decode the pins into decodedClientPins")

	// --disable-authentication may be combined with --verify-spki-pin on the
	// client: it only suppresses the client's own certificate, while the pin
	// still authenticates the server (the DoT-style no-client-cert deployment).
	reset()
	*clientVerifySpkiPin = []string{validPin}
	*clientDisableAuth = true
	assert.Nil(t, validateClientPin(), "--verify-spki-pin with --disable-authentication should be valid")

	// Malformed pins are rejected at validation time (before listen/dial).
	reset()
	*clientVerifySpkiPin = []string{"sha256:not valid base64 @@@"}
	assert.NotNil(t, validateClientPin(), "malformed --verify-spki-pin should be rejected at validation")
	assert.Nil(t, decodedClientPins, "no pins should be stored on validation failure")

	// A successful decode must not leak into a later in-process run that omits
	// --verify-spki-pin: validateClientPin resets decodedClientPins itself, so
	// this holds even without the test's own reset() clearing it.
	reset()
	*clientVerifySpkiPin = []string{validPin, validPin}
	assert.Nil(t, validateClientPin(), "valid --verify-spki-pin should be accepted")
	assert.Equal(t, 2, len(decodedClientPins))
	*clientVerifySpkiPin = nil
	assert.Nil(t, validateClientPin(), "baseline without --verify-spki-pin should be accepted")
	assert.Nil(t, decodedClientPins, "decodedClientPins from the earlier run should not leak into this one")

	conflicts := map[string]func(){
		"--verify-cn":        func() { *clientAllowedCNs = []string{"test"} },
		"--verify-ou":        func() { *clientAllowedOUs = []string{"test"} },
		"--verify-dns-san":   func() { *clientAllowedDNSs = []string{"test"} },
		"--verify-ip-san":    func() { *clientAllowedIPs = []net.IP{net.IPv4(0, 0, 0, 0)} },
		"--verify-uri-san":   func() { *clientAllowedURIs = []string{"spiffe://example.com/*"} },
		"--verify-policy":    func() { *clientAllowPolicy = "policy" },
		"--verify-query":     func() { *clientAllowQuery = "query" },
		"--use-workload-api": func() { *useWorkloadAPI = true },
	}
	for name, set := range conflicts {
		reset()
		*clientVerifySpkiPin = []string{validPin}
		set()
		err := validateClientPin()
		if assert.NotNil(t, err, "--verify-spki-pin must be mutually exclusive with "+name) {
			assert.Contains(t, err.Error(), "--verify-spki-pin is mutually exclusive")
		}
	}
}

func TestAllowsLocalhost(t *testing.T) {
	*serverUnsafeTarget = false
	assert.True(t, consideredSafe("localhost:1234"), "localhost should be allowed")
	assert.True(t, consideredSafe("127.0.0.1:1234"), "127.0.0.1 should be allowed")
	assert.True(t, consideredSafe("[::1]:1234"), "[::1] should be allowed")
	assert.True(t, consideredSafe("unix:/tmp/foo"), "unix:/tmp/foo should be allowed")
	assert.True(t, consideredSafe("systemd:foo"), "systemd:foo should be allowed")
	assert.True(t, consideredSafe("launchd:foo"), "launchd:foo should be allowed")
}

func TestDisallowsFooDotCom(t *testing.T) {
	*serverUnsafeTarget = false
	assert.False(t, consideredSafe("foo.com:1234"), "foo.com should be disallowed")
	assert.False(t, consideredSafe("alocalhost.com:1234"), "alocalhost.com should be disallowed")
	assert.False(t, consideredSafe("localhost.com.foo.com:1234"), "localhost.com.foo.com should be disallowed")
	assert.False(t, consideredSafe("74.122.190.83:1234"), "random ip address should be disallowed")
}

func TestServerBackendDialerError(t *testing.T) {
	original := *serverForwardAddress
	defer func() { *serverForwardAddress = original }()

	*serverForwardAddress = "invalid"
	_, err := serverBackendDialer()
	assert.NotNil(t, err, "invalid forward address should not have dialer")
}

func TestValidateServerTargetRejectsSystemd(t *testing.T) {
	original := *serverForwardAddress
	defer func() { *serverForwardAddress = original }()

	*serverForwardAddress = "systemd:foo"
	err := validateServerTarget()
	assert.NotNil(t, err, "systemd: target should be rejected")
	if err != nil {
		assert.Contains(t, err.Error(), "systemd", "error message should mention the offending network")
	}
}

func TestValidateServerTargetRejectsLaunchd(t *testing.T) {
	original := *serverForwardAddress
	defer func() { *serverForwardAddress = original }()

	*serverForwardAddress = "launchd:foo"
	err := validateServerTarget()
	assert.NotNil(t, err, "launchd: target should be rejected")
	if err != nil {
		assert.Contains(t, err.Error(), "launchd", "error message should mention the offending network")
	}
}

func TestValidateServerTargetAcceptsUnix(t *testing.T) {
	original := *serverForwardAddress
	defer func() { *serverForwardAddress = original }()

	*serverForwardAddress = "unix:/tmp/ghostunnel-target-test.sock"
	assert.Nil(t, validateServerTarget(), "unix: target should be accepted")
}

func TestServerBackendDialerAcceptsUnix(t *testing.T) {
	original := *serverForwardAddress
	defer func() { *serverForwardAddress = original }()

	*serverForwardAddress = "unix:/tmp/ghostunnel-target-test.sock"
	dial, err := serverBackendDialer()
	assert.Nil(t, err, "unix: target should be accepted")
	assert.NotNil(t, dial, "unix: target should produce a dialer")
}

func TestValidateClientTargetRejectsUnix(t *testing.T) {
	original := *clientForwardAddress
	defer func() { *clientForwardAddress = original }()

	*clientForwardAddress = "unix:/tmp/foo"
	err := validateClientTarget()
	assert.NotNil(t, err, "unix: target should be rejected for client mode")
	if err != nil {
		assert.Contains(t, err.Error(), "unix", "error message should mention the offending network")
	}
}

func TestValidateClientTargetRejectsSystemd(t *testing.T) {
	original := *clientForwardAddress
	defer func() { *clientForwardAddress = original }()

	*clientForwardAddress = "systemd:foo"
	err := validateClientTarget()
	assert.NotNil(t, err, "systemd: target should be rejected for client mode")
	if err != nil {
		assert.Contains(t, err.Error(), "systemd", "error message should mention the offending network")
	}
}

func TestValidateClientTargetRejectsLaunchd(t *testing.T) {
	original := *clientForwardAddress
	defer func() { *clientForwardAddress = original }()

	*clientForwardAddress = "launchd:foo"
	err := validateClientTarget()
	assert.NotNil(t, err, "launchd: target should be rejected for client mode")
	if err != nil {
		assert.Contains(t, err.Error(), "launchd", "error message should mention the offending network")
	}
}

func TestValidateClientTargetAcceptsTCP(t *testing.T) {
	original := *clientForwardAddress
	defer func() { *clientForwardAddress = original }()

	*clientForwardAddress = "localhost:8443"
	assert.Nil(t, validateClientTarget(), "localhost:PORT target should be accepted for client mode")
}

func TestValidateClientTargetRejectsMalformed(t *testing.T) {
	original := *clientForwardAddress
	defer func() { *clientForwardAddress = original }()

	*clientForwardAddress = "no-port-here"
	err := validateClientTarget()
	assert.NotNil(t, err, "malformed target should be rejected")
	if err != nil {
		assert.Contains(t, err.Error(), "invalid --target address", "error should identify the bad flag")
	}
}

func TestValidateServerTargetRejectsMalformed(t *testing.T) {
	originalAddr := *serverForwardAddress
	originalUnsafe := *serverUnsafeTarget
	defer func() {
		*serverForwardAddress = originalAddr
		*serverUnsafeTarget = originalUnsafe
	}()

	// --unsafe-target bypasses the consideredSafe gate so the parse path
	// runs on a malformed input.
	*serverUnsafeTarget = true
	*serverForwardAddress = "no-port-here"
	err := validateServerTarget()
	assert.NotNil(t, err, "malformed target should be rejected even with --unsafe-target")
	if err != nil {
		assert.Contains(t, err.Error(), "invalid --target address", "error should identify the bad flag")
	}
}

func TestValidateStatusAddress(t *testing.T) {
	original := *statusAddress
	defer func() { *statusAddress = original }()

	cases := []struct {
		input     string
		wantErr   bool
		errSubstr string
	}{
		{input: "", wantErr: false},
		{input: "localhost:8080", wantErr: false},
		{input: "http://localhost:8080", wantErr: false},
		{input: "https://localhost:8080", wantErr: false},
		{input: "unix:/tmp/foo", wantErr: false},
		{input: "systemd:status", wantErr: false},
		{input: "launchd:status", wantErr: false},
		{input: "http://unix:/tmp/foo", wantErr: true, errSubstr: "unix"},
		{input: "http://systemd:status", wantErr: true, errSubstr: "systemd"},
		{input: "http://launchd:status", wantErr: true, errSubstr: "launchd"},
		{input: "https://unix:/tmp/foo", wantErr: true, errSubstr: "unix"},
		{input: "https://systemd:status", wantErr: true, errSubstr: "systemd"},
		{input: "https://launchd:status", wantErr: true, errSubstr: "launchd"},
		{input: "garbage", wantErr: true},
	}
	for _, c := range cases {
		*statusAddress = c.input
		err := validateStatusAddress()
		if c.wantErr {
			assert.NotNil(t, err, "input %q should be rejected", c.input)
			if err != nil && c.errSubstr != "" {
				assert.Contains(t, err.Error(), c.errSubstr, "error for %q should mention %q", c.input, c.errSubstr)
			}
		} else {
			assert.Nil(t, err, "input %q should be accepted", c.input)
		}
	}
}

func TestInvalidCABundle(t *testing.T) {
	cmd := []string{
		"server",
		"--cacert", "/dev/null",
		"--target", "localhost:8080",
		"--keystore", "keystore.p12",
		"--listen", "localhost:8080",
	}
	if runtime.GOOS == "linux" {
		// Disable landlock so we don't inadvertently affect later unit tests.
		cmd = append(cmd, "--disable-landlock")
	}
	err := run(cmd)
	assert.NotNil(t, err, "invalid CA bundle should exit with error")
}

func TestProxyLoggingFlags(t *testing.T) {
	assert.Equal(t, proxyLoggerFlags([]string{""}), proxy.LogEverything)
	assert.Equal(t, proxyLoggerFlags([]string{"conns"}), proxy.LogEverything & ^proxy.LogConnections)
	assert.Equal(t, proxyLoggerFlags([]string{"conn-errs"}), proxy.LogEverything & ^proxy.LogConnectionErrors)
	assert.Equal(t, proxyLoggerFlags([]string{"handshake-errs"}), proxy.LogEverything & ^proxy.LogHandshakeErrors)
	assert.Equal(t, proxyLoggerFlags([]string{"conns", "handshake-errs"}), proxy.LogConnectionErrors)
	assert.Equal(t, proxyLoggerFlags([]string{"conn-errs", "handshake-errs"}), proxy.LogConnections)
	assert.Equal(t, proxyLoggerFlags([]string{"conns", "conn-errs"}), proxy.LogHandshakeErrors)
}

func TestServerProxyProtoMode(t *testing.T) {
	// Save and restore globals
	origProto := *serverProxyProtocol
	origMode := *serverProxyProtocolMode
	defer func() {
		*serverProxyProtocol = origProto
		*serverProxyProtocolMode = origMode
	}()

	// Neither flag set → Off
	*serverProxyProtocol = false
	*serverProxyProtocolMode = ""
	assert.Equal(t, proxy.ProxyProtocolOff, serverProxyProtoMode())

	// Only --proxy-protocol → Conn
	*serverProxyProtocol = true
	*serverProxyProtocolMode = ""
	assert.Equal(t, proxy.ProxyProtocolConn, serverProxyProtoMode())

	// Only --proxy-protocol-mode=tls → TLS
	*serverProxyProtocol = false
	*serverProxyProtocolMode = "tls"
	assert.Equal(t, proxy.ProxyProtocolTLS, serverProxyProtoMode())

	// Only --proxy-protocol-mode=tls-full → TLSFull
	*serverProxyProtocol = false
	*serverProxyProtocolMode = "tls-full"
	assert.Equal(t, proxy.ProxyProtocolTLSFull, serverProxyProtoMode())

	// Only --proxy-protocol-mode=conn → Conn
	*serverProxyProtocol = false
	*serverProxyProtocolMode = "conn"
	assert.Equal(t, proxy.ProxyProtocolConn, serverProxyProtoMode())

	// Both set: validation rejects this combination
	*serverProxyProtocol = true
	*serverProxyProtocolMode = "tls-full"
	err := validateServerProxyProtocol()
	assert.ErrorContains(t, err, "mutually exclusive")
}

// failingTLSConfigSource is a mock TLSConfigSource that always returns errors
type failingTLSConfigSource struct{}

func (f *failingTLSConfigSource) Reload() error {
	return nil
}

func (f *failingTLSConfigSource) CanServe() bool {
	return false
}

func (f *failingTLSConfigSource) GetClientConfig(base *tls.Config) (certloader.TLSClientConfig, error) {
	return nil, errors.New("test error: GetClientConfig failed")
}

func (f *failingTLSConfigSource) GetServerConfig(base *tls.Config) (certloader.TLSServerConfig, error) {
	return nil, errors.New("test error: GetServerConfig failed")
}

func TestGetServerConfigReturnsError(t *testing.T) {
	source := &failingTLSConfigSource{}
	_, err := getServerConfig(source, nil)
	if err == nil {
		t.Error("expected error when GetServerConfig fails")
	}
}

func TestGetClientConfigReturnsError(t *testing.T) {
	source := &failingTLSConfigSource{}
	_, err := getClientConfig(source, nil)
	if err == nil {
		t.Error("expected error when GetClientConfig fails")
	}
}

// writeTempFile creates a temp file with the given content and returns its path.
// The caller should defer os.Remove on the returned path.
func writeTempFile(t *testing.T, prefix string, content []byte) string {
	t.Helper()
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(content); err != nil {
		t.Fatal(err)
	}
	f.Sync()
	f.Close()
	return f.Name()
}

func TestGetTLSConfigSourceCertPath(t *testing.T) {
	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	// Save and restore global flag state
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
	}()

	*useWorkloadAPI = false
	*serverAutoACMEFQDN = ""
	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should be able to create TLS config source from cert/key files")
	assert.NotNil(t, source, "TLS config source should not be nil")
}

func TestGetTLSConfigSourceKeystore(t *testing.T) {
	ksFile := writeTempFile(t, "test-ks-*.p12", testKeystore)
	defer os.Remove(ksFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	origKeystorePass := *keystorePass
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
		*keystorePass = origKeystorePass
	}()

	*useWorkloadAPI = false
	*serverAutoACMEFQDN = ""
	*keystorePath = ksFile
	*certPath = ""
	*keyPath = ""
	*caBundlePath = caFile
	*keystorePass = testKeystorePassword

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should be able to create TLS config source from keystore")
	assert.NotNil(t, source, "TLS config source should not be nil")
}

func TestGetTLSConfigSourceInvalidCert(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
	}()

	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*useWorkloadAPI = false
	*serverAutoACMEFQDN = ""
	*keystorePath = "nonexistent-keystore.p12"
	*certPath = ""
	*keyPath = ""
	*caBundlePath = caFile

	_, err := getTLSConfigSource(false)
	assert.NotNil(t, err, "should fail with invalid cert path")
}

func TestGetTLSConfigSourceNoCert(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
	}()

	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*useWorkloadAPI = false
	*serverAutoACMEFQDN = ""
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""
	*caBundlePath = caFile

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should be able to create TLS config source with no cert")
	assert.NotNil(t, source, "TLS config source should not be nil")
}

func TestServerValidateFlagsACMEMissingEmail(t *testing.T) {
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	origServerAutoACMEEmail := *serverAutoACMEEmail
	origServerAutoACMEAgreedTOS := *serverAutoACMEAgreedTOS
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origServerDisableAuth := *serverDisableAuth
	origServerAllowAll := *serverAllowAll
	origServerAllowedCNs := *serverAllowedCNs
	origServerAllowedOUs := *serverAllowedOUs
	origServerAllowedDNSs := *serverAllowedDNSs
	origServerAllowedIPs := *serverAllowedIPs
	origServerAllowedURIs := *serverAllowedURIs
	origServerAllowPolicy := *serverAllowPolicy
	origServerAllowQuery := *serverAllowQuery
	origServerForwardAddress := *serverForwardAddress
	origServerUnsafeTarget := *serverUnsafeTarget
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
		*serverAutoACMEEmail = origServerAutoACMEEmail
		*serverAutoACMEAgreedTOS = origServerAutoACMEAgreedTOS
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*serverDisableAuth = origServerDisableAuth
		*serverAllowAll = origServerAllowAll
		*serverAllowedCNs = origServerAllowedCNs
		*serverAllowedOUs = origServerAllowedOUs
		*serverAllowedDNSs = origServerAllowedDNSs
		*serverAllowedIPs = origServerAllowedIPs
		*serverAllowedURIs = origServerAllowedURIs
		*serverAllowPolicy = origServerAllowPolicy
		*serverAllowQuery = origServerAllowQuery
		*serverForwardAddress = origServerForwardAddress
		*serverUnsafeTarget = origServerUnsafeTarget
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	// ACME is the only credential source
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""
	*serverAutoACMEFQDN = "example.com"
	*serverAutoACMEEmail = ""
	*serverAutoACMEAgreedTOS = true
	// Use disable-authentication to bypass access control checks
	*serverDisableAuth = true
	*serverAllowAll = false
	*serverAllowedCNs = nil
	*serverAllowedOUs = nil
	*serverAllowedDNSs = nil
	*serverAllowedIPs = nil
	*serverAllowedURIs = nil
	*serverAllowPolicy = ""
	*serverAllowQuery = ""
	*serverForwardAddress = "localhost:8080"
	*serverUnsafeTarget = false
	*enabledCipherSuites = "AES,CHACHA"

	err := serverValidateFlags()
	assert.NotNil(t, err, "ACME without email should be rejected")
	assert.Contains(t, err.Error(), "auto-acme-email", "error should mention missing email")
}

func TestServerValidateFlagsACMEMissingTOS(t *testing.T) {
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	origServerAutoACMEEmail := *serverAutoACMEEmail
	origServerAutoACMEAgreedTOS := *serverAutoACMEAgreedTOS
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origServerDisableAuth := *serverDisableAuth
	origServerAllowAll := *serverAllowAll
	origServerAllowedCNs := *serverAllowedCNs
	origServerAllowedOUs := *serverAllowedOUs
	origServerAllowedDNSs := *serverAllowedDNSs
	origServerAllowedIPs := *serverAllowedIPs
	origServerAllowedURIs := *serverAllowedURIs
	origServerAllowPolicy := *serverAllowPolicy
	origServerAllowQuery := *serverAllowQuery
	origServerForwardAddress := *serverForwardAddress
	origServerUnsafeTarget := *serverUnsafeTarget
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
		*serverAutoACMEEmail = origServerAutoACMEEmail
		*serverAutoACMEAgreedTOS = origServerAutoACMEAgreedTOS
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*serverDisableAuth = origServerDisableAuth
		*serverAllowAll = origServerAllowAll
		*serverAllowedCNs = origServerAllowedCNs
		*serverAllowedOUs = origServerAllowedOUs
		*serverAllowedDNSs = origServerAllowedDNSs
		*serverAllowedIPs = origServerAllowedIPs
		*serverAllowedURIs = origServerAllowedURIs
		*serverAllowPolicy = origServerAllowPolicy
		*serverAllowQuery = origServerAllowQuery
		*serverForwardAddress = origServerForwardAddress
		*serverUnsafeTarget = origServerUnsafeTarget
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	// ACME is the only credential source
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""
	*serverAutoACMEFQDN = "example.com"
	*serverAutoACMEEmail = "test@example.com"
	*serverAutoACMEAgreedTOS = false
	// Use disable-authentication to bypass access control checks
	*serverDisableAuth = true
	*serverAllowAll = false
	*serverAllowedCNs = nil
	*serverAllowedOUs = nil
	*serverAllowedDNSs = nil
	*serverAllowedIPs = nil
	*serverAllowedURIs = nil
	*serverAllowPolicy = ""
	*serverAllowQuery = ""
	*serverForwardAddress = "localhost:8080"
	*serverUnsafeTarget = false
	*enabledCipherSuites = "AES,CHACHA"

	err := serverValidateFlags()
	assert.NotNil(t, err, "ACME without TOS agreement should be rejected")
	assert.Contains(t, err.Error(), "auto-acme-agree-to-tos", "error should mention missing TOS")
}

func TestClientBackendDialerWithOPA(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping on windows")
	}

	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origClientServerName := *clientServerName
	origClientAllowedURIs := *clientAllowedURIs
	origClientAllowPolicy := *clientAllowPolicy
	origClientAllowQuery := *clientAllowQuery
	origConnectTimeout := *connectTimeout
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*clientServerName = origClientServerName
		*clientAllowedURIs = origClientAllowedURIs
		*clientAllowPolicy = origClientAllowPolicy
		*clientAllowQuery = origClientAllowQuery
		*connectTimeout = origConnectTimeout
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	// Create a temp OPA policy file
	policyFile, err := os.CreateTemp("", "test-policy-*.rego")
	assert.Nil(t, err)
	defer os.Remove(policyFile.Name())

	_, err = policyFile.WriteString(`package policy
import input
default allow := true
`)
	assert.Nil(t, err)
	policyFile.Sync()
	policyFile.Close()

	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile
	*clientServerName = "localhost"
	*clientAllowedURIs = []string{"spiffe://ghostunnel/*"}
	*clientAllowPolicy = policyFile.Name()
	*clientAllowQuery = "data.policy.allow"
	*connectTimeout = 10 * time.Second
	*enabledCipherSuites = "AES,CHACHA"

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should create TLS config source")

	dial, regoPolicy, err := clientBackendDialer(source, "tcp", "localhost:8443", "localhost")
	assert.Nil(t, err, "should create client backend dialer with OPA")
	assert.NotNil(t, dial, "dialer should not be nil")
	assert.NotNil(t, regoPolicy, "rego policy should not be nil")
}

func TestClientBackendDialerWithServerNameOverride(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origClientServerName := *clientServerName
	origClientAllowedURIs := *clientAllowedURIs
	origClientAllowPolicy := *clientAllowPolicy
	origClientAllowQuery := *clientAllowQuery
	origConnectTimeout := *connectTimeout
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*clientServerName = origClientServerName
		*clientAllowedURIs = origClientAllowedURIs
		*clientAllowPolicy = origClientAllowPolicy
		*clientAllowQuery = origClientAllowQuery
		*connectTimeout = origConnectTimeout
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile
	*clientServerName = "override.example.com"
	*clientAllowedURIs = nil
	*clientAllowPolicy = ""
	*clientAllowQuery = ""
	*connectTimeout = 10 * time.Second
	*enabledCipherSuites = "AES,CHACHA"

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should create TLS config source")

	dial, regoPolicy, err := clientBackendDialer(source, "tcp", "localhost:8443", "localhost")
	assert.Nil(t, err, "should create client backend dialer with server name override")
	assert.NotNil(t, dial, "dialer should not be nil")
	assert.Nil(t, regoPolicy, "rego policy should be nil when not configured")
}

func TestClientBackendDialerInvalidURI(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origClientServerName := *clientServerName
	origClientAllowedURIs := *clientAllowedURIs
	origClientAllowPolicy := *clientAllowPolicy
	origClientAllowQuery := *clientAllowQuery
	origConnectTimeout := *connectTimeout
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*clientServerName = origClientServerName
		*clientAllowedURIs = origClientAllowedURIs
		*clientAllowPolicy = origClientAllowPolicy
		*clientAllowQuery = origClientAllowQuery
		*connectTimeout = origConnectTimeout
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile
	*clientServerName = ""
	// An empty string is the only invalid URI pattern for the wildcard compiler
	*clientAllowedURIs = []string{""}
	*clientAllowPolicy = ""
	*clientAllowQuery = ""
	*connectTimeout = 10 * time.Second
	*enabledCipherSuites = "AES,CHACHA"

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should create TLS config source")

	_, _, err = clientBackendDialer(source, "tcp", "localhost:8443", "localhost")
	assert.NotNil(t, err, "should fail with empty URI pattern")
}

func TestClientBackendDialerInvalidOPAPolicy(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origClientServerName := *clientServerName
	origClientAllowedURIs := *clientAllowedURIs
	origClientAllowPolicy := *clientAllowPolicy
	origClientAllowQuery := *clientAllowQuery
	origConnectTimeout := *connectTimeout
	origEnabledCipherSuites := *enabledCipherSuites
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*clientServerName = origClientServerName
		*clientAllowedURIs = origClientAllowedURIs
		*clientAllowPolicy = origClientAllowPolicy
		*clientAllowQuery = origClientAllowQuery
		*connectTimeout = origConnectTimeout
		*enabledCipherSuites = origEnabledCipherSuites
	}()

	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile
	*clientServerName = ""
	*clientAllowedURIs = nil
	*clientAllowPolicy = "/nonexistent/policy.rego"
	*clientAllowQuery = "data.policy.allow"
	*connectTimeout = 10 * time.Second
	*enabledCipherSuites = "AES,CHACHA"

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should create TLS config source")

	_, _, err = clientBackendDialer(source, "tcp", "localhost:8443", "localhost")
	assert.NotNil(t, err, "should fail with invalid OPA policy path")
}

func TestGetTLSConfigSourceWorkloadAPI(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origUseWorkloadAPIAddr := *useWorkloadAPIAddr
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*useWorkloadAPIAddr = origUseWorkloadAPIAddr
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
	}()

	// SPIFFE client creation succeeds even with unreachable address (lazy connect).
	// This test exercises the SPIFFE branch in getTLSConfigSource (main.go:908-914).
	*useWorkloadAPI = true
	*useWorkloadAPIAddr = "tcp://127.0.0.1:1"
	*serverAutoACMEFQDN = ""
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""

	source, err := getTLSConfigSource(false)
	assert.Nil(t, err, "SPIFFE source creation should succeed (lazy connection)")
	assert.NotNil(t, source, "should return a TLS config source from workload API")
}

func TestGetTLSConfigSourceACMEError(t *testing.T) {
	acmeConfig := certloader.ACMEConfig{
		FQDN:        "test.example.com",
		Email:       "test@example.com",
		TOSAgreed:   true,
		TestCAURL:   "https://127.0.0.1:1/directory",
		MaxAttempts: 1,
	}

	_, err := certloader.TLSConfigSourceFromACME(&acmeConfig)
	assert.NotNil(t, err, "should fail to obtain ACME cert from unreachable CA")
}

func TestValidateCipherSuitesUnsafe(t *testing.T) {
	origEnabledCipherSuites := *enabledCipherSuites
	origAllowUnsafeCipherSuites := *allowUnsafeCipherSuites
	defer func() {
		*enabledCipherSuites = origEnabledCipherSuites
		*allowUnsafeCipherSuites = origAllowUnsafeCipherSuites
	}()

	*enabledCipherSuites = "UNSAFE-AZURE"
	*allowUnsafeCipherSuites = false
	err := validateCipherSuites()
	assert.NotNil(t, err, "should reject unsafe cipher suites without flag")

	*allowUnsafeCipherSuites = true
	err = validateCipherSuites()
	assert.Nil(t, err, "should allow unsafe cipher suites with flag")
}

func TestValidateServerOPANoFlags(t *testing.T) {
	err := validateServerOPA(false)
	assert.Nil(t, err, "validateServerOPA must return nil when no OPA flags are set")
}

// TestGetTLSConfigSourceSpiffeError exercises the SPIFFE branch error path
// in getTLSConfigSource. Using a hostname (not an IP) in the workload-API
// address fails synchronously inside spiffeApi.New -> setAddress ->
// parseTargetFromURLAddr (the host component must be an IP literal).
func TestGetTLSConfigSourceSpiffeError(t *testing.T) {
	origUse := *useWorkloadAPI
	origAddr := *useWorkloadAPIAddr
	origACME := *serverAutoACMEFQDN
	origKeystore := *keystorePath
	origCert := *certPath
	origKey := *keyPath
	defer func() {
		*useWorkloadAPI = origUse
		*useWorkloadAPIAddr = origAddr
		*serverAutoACMEFQDN = origACME
		*keystorePath = origKeystore
		*certPath = origCert
		*keyPath = origKey
	}()

	*useWorkloadAPI = true
	// Hostname (not an IP) is rejected by SPIFFE address validation in
	// spiffeApi.New -> setAddress -> parseTargetFromURLAddr.
	*useWorkloadAPIAddr = "tcp://example.com:8081"
	*serverAutoACMEFQDN = ""
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""

	source, err := getTLSConfigSource(false)
	assert.NotNil(t, err, "expected SPIFFE init failure on invalid address")
	assert.Nil(t, source)
}

// TestUseWorkloadAPIAddrImpliesUseWorkloadAPI: --use-workload-api-addr alone
// must enable --use-workload-api. Otherwise users have to set both flags.
func TestUseWorkloadAPIAddrImpliesUseWorkloadAPI(t *testing.T) {
	origUse := *useWorkloadAPI
	origAddr := *useWorkloadAPIAddr
	defer func() {
		*useWorkloadAPI = origUse
		*useWorkloadAPIAddr = origAddr
	}()

	*useWorkloadAPI = false
	*useWorkloadAPIAddr = "tcp://127.0.0.1:1"

	applyFlagImplications()
	assert.True(t, *useWorkloadAPI, "setting --use-workload-api-addr must imply --use-workload-api")
}

// TestCheckBackendStatusInvalidURLNonStatus is intentionally absent — the
// equivalent test is in status_test.go (TestCheckBackendStatusInvalidURL).
//
// TestSignalHandlerReloadAndShutdown lives in unix_test.go because it relies
// on POSIX signal delivery (SIGHUP) which is unavailable on Windows.

// TestServerListenEarlyErrors covers two early-return failure paths in
// serverListen that occur before any listener is opened:
//  1. buildServerConfig fails on a bad cipher suite.
//  2. wildcard.CompileList fails on an invalid URI pattern.
//
// Both return before serverListen dereferences env, so a zero-value
// *Environment is sufficient. The previously-tested policy.LoadFromPath
// failure path now lives in run() (loaded before serverListen is called),
// so it is no longer exercised here.
func TestServerListenEarlyErrors(t *testing.T) {
	origPolicy := *serverAllowPolicy
	origQuery := *serverAllowQuery
	origURIs := *serverAllowedURIs
	origAllowAll := *serverAllowAll
	origCiphers := *enabledCipherSuites
	origMaxTLS := *maxTLSVersion
	defer func() {
		*serverAllowPolicy = origPolicy
		*serverAllowQuery = origQuery
		*serverAllowedURIs = origURIs
		*serverAllowAll = origAllowAll
		*enabledCipherSuites = origCiphers
		*maxTLSVersion = origMaxTLS
	}()

	cases := []struct {
		name       string
		setup      func()
		wantSubstr string // matched case-insensitively; "" means any non-nil error
	}{
		{
			name: "bad cipher suite",
			setup: func() {
				*enabledCipherSuites = "BOGUS-SUITE"
				*maxTLSVersion = ""
				*serverAllowedURIs = nil
				*serverAllowPolicy = ""
				*serverAllowQuery = ""
				*serverAllowAll = true
			},
			wantSubstr: "cipher suite",
		},
		{
			name: "invalid URI pattern",
			setup: func() {
				*enabledCipherSuites = "AES,CHACHA"
				*maxTLSVersion = ""
				*serverAllowedURIs = []string{""} // empty pattern fails wildcard.Compile
				*serverAllowPolicy = ""
				*serverAllowQuery = ""
				*serverAllowAll = false
			},
			wantSubstr: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			env := &Environment{}
			err := serverListen(env, nil)
			assert.NotNil(t, err, "expected non-nil error from serverListen")
			if c.wantSubstr != "" && err != nil {
				assert.Contains(t, strings.ToLower(err.Error()), c.wantSubstr)
			}
		})
	}
}

// TestClientListenSocketOpenFails covers the clientListen early-return path
// when socket.ParseAndOpen fails. Using a unix socket whose parent directory
// does not exist exercises the failure inside socket.Open (after ParseAddress
// succeeds), driving the err branch of clientListen.
func TestClientListenSocketOpenFails(t *testing.T) {
	orig := *clientListenAddress
	t.Cleanup(func() { *clientListenAddress = orig })

	*clientListenAddress = "unix:/nonexistent/dir/sock.sock"

	err := clientListen(&Environment{})
	assert.NotNil(t, err, "expected error for invalid socket address")
	if err != nil {
		// Loose assertion to stay resilient to error wording across OSes.
		msg := strings.ToLower(err.Error())
		assert.True(t,
			strings.Contains(msg, "no such") ||
				strings.Contains(msg, "socket") ||
				strings.Contains(msg, "listen") ||
				strings.Contains(msg, "directory"),
			"unexpected error: %q", err.Error())
	}
}

// fakeNonContextDialer is a netproxy.Dialer that intentionally does NOT
// implement netproxy.ContextDialer. Used to exercise the type-assertion
// failure branch in clientBackendDialer.
type fakeNonContextDialer struct{ forward netproxy.Dialer }

func (d *fakeNonContextDialer) Dial(network, addr string) (net.Conn, error) {
	return d.forward.Dial(network, addr)
}

// TestClientBackendDialerProxyNotContextDialer covers the branch in
// clientBackendDialer (~main.go:964-969) where the dialer returned by
// netproxy.FromURL does not implement netproxy.ContextDialer, producing the
// "did not implement context dialing" error before any actual dialing.
func TestClientBackendDialerProxyNotContextDialer(t *testing.T) {
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origClientServerName := *clientServerName
	origClientAllowedURIs := *clientAllowedURIs
	origClientAllowPolicy := *clientAllowPolicy
	origClientAllowQuery := *clientAllowQuery
	origConnectTimeout := *connectTimeout
	origEnabledCipherSuites := *enabledCipherSuites
	origClientProxy := *clientProxy
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*clientServerName = origClientServerName
		*clientAllowedURIs = origClientAllowedURIs
		*clientAllowPolicy = origClientAllowPolicy
		*clientAllowQuery = origClientAllowQuery
		*connectTimeout = origConnectTimeout
		*enabledCipherSuites = origEnabledCipherSuites
		*clientProxy = origClientProxy
	}()

	certFile := writeTempFile(t, "test-cert-*.pem", []byte(testKeystoreCertOnly))
	defer os.Remove(certFile)
	keyFile := writeTempFile(t, "test-key-*.pem", []byte(testKeystoreKeyPath))
	defer os.Remove(keyFile)
	caFile := writeTempFile(t, "test-ca-*.pem", []byte(testCertificate))
	defer os.Remove(caFile)

	*keystorePath = ""
	*certPath = certFile
	*keyPath = keyFile
	*caBundlePath = caFile
	*clientServerName = "localhost"
	*clientAllowedURIs = nil
	*clientAllowPolicy = ""
	*clientAllowQuery = ""
	*connectTimeout = 5 * time.Second
	*enabledCipherSuites = "AES,CHACHA"

	// Register a custom proxy scheme whose factory returns a Dial-only dialer.
	// The golang.org/x/net/proxy registry has no remove API, so re-registration
	// in the same process is idempotent overwrite. Using a unique scheme name
	// avoids interference with other tests.
	netproxy.RegisterDialerType("testnoctx", func(u *url.URL, fwd netproxy.Dialer) (netproxy.Dialer, error) {
		return &fakeNonContextDialer{fwd}, nil
	})

	proxyURL, err := url.Parse("testnoctx://dummy:9999")
	assert.Nil(t, err)
	*clientProxy = proxyURL

	src, err := getTLSConfigSource(false)
	assert.Nil(t, err, "should create TLS config source")

	_, _, err = clientBackendDialer(src, "tcp", "localhost:8443", "localhost")
	assert.NotNil(t, err, "should error when proxy dialer is not a ContextDialer")
	if err != nil {
		assert.Contains(t, err.Error(), "did not implement context dialing")
	}
}

// TestValidateServerOPA exercises the partial-OPA-flag and mutual-exclusivity
// branches of validateServerOPA directly. The early-return path is covered by
// TestValidateServerOPANoFlags above.
func TestValidateServerOPA(t *testing.T) {
	origPolicy, origQuery := *serverAllowPolicy, *serverAllowQuery
	t.Cleanup(func() {
		*serverAllowPolicy = origPolicy
		*serverAllowQuery = origQuery
	})

	cases := []struct {
		name          string
		hasOPAFlags   bool
		policy, query string
		wantErrSubstr string // "" means expect nil
	}{
		{"no flags", false, "", "", ""},
		{"OPA only - missing query", true, "policy", "", "have to be used together"},
		{"OPA only - missing policy", true, "", "query", "have to be used together"},
		{"OPA combined with access flags", true, "policy", "query", ""},
		{"OPA only - both set", true, "policy", "query", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			*serverAllowPolicy = c.policy
			*serverAllowQuery = c.query

			err := validateServerOPA(c.hasOPAFlags)
			if c.wantErrSubstr == "" {
				assert.NoError(t, err)
				return
			}
			if assert.Error(t, err) {
				assert.Contains(t, err.Error(), c.wantErrSubstr)
			}
		})
	}
}

// TestShutdownHandlerRejectsNonPost verifies that requests other than POST
// return 405 Method Not Allowed and do not signal the shutdown channel.
func TestShutdownHandlerRejectsNonPost(t *testing.T) {
	env := &Environment{
		shutdownChannel: make(chan bool, 1),
	}

	req := httptest.NewRequest(http.MethodGet, "/_shutdown", nil)
	rec := httptest.NewRecorder()
	env.shutdownHandler(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "GET should not be allowed")

	select {
	case <-env.shutdownChannel:
		t.Fatal("non-POST request should not signal shutdown")
	default:
	}
}

// TestShutdownHandlerSignalsOnce verifies that a POST signals the shutdown
// channel exactly once and returns 200 OK.
func TestShutdownHandlerSignalsOnce(t *testing.T) {
	env := &Environment{
		shutdownChannel: make(chan bool, 1),
	}

	req := httptest.NewRequest(http.MethodPost, "/_shutdown", nil)
	rec := httptest.NewRecorder()
	env.shutdownHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	select {
	case <-env.shutdownChannel:
		// expected
	default:
		t.Fatal("POST should have signalled shutdown channel")
	}
}

// TestShutdownHandlerConcurrentPosts ensures that concurrent POSTs to the
// shutdown handler all return promptly even though the channel buffer can
// only absorb one value and there is no reader. Without the non-blocking
// send, surplus handler goroutines would block forever on the channel,
// stalling graceful shutdown of the status HTTP server.
func TestShutdownHandlerConcurrentPosts(t *testing.T) {
	env := &Environment{
		// Capacity 1 mirrors the production setup. No goroutine reads from
		// it, so after the first send the buffer is full and a blocking
		// send would deadlock.
		shutdownChannel: make(chan bool, 1),
	}

	const concurrent = 16

	var wg sync.WaitGroup
	wg.Add(concurrent)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	for range concurrent {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/_shutdown", nil)
			rec := httptest.NewRecorder()
			env.shutdownHandler(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}()
	}

	select {
	case <-done:
		// All handler goroutines returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown handler blocked on channel send: at least one of the concurrent POSTs did not return promptly")
	}

	// The channel must contain exactly one value: the first POST that won
	// the race; all subsequent sends should have been dropped by the
	// non-blocking select.
	select {
	case <-env.shutdownChannel:
	default:
		t.Fatal("expected exactly one buffered shutdown signal")
	}
	select {
	case <-env.shutdownChannel:
		t.Fatal("expected at most one buffered shutdown signal, got more")
	default:
	}
}

// TestLoadOPAPolicy covers the helper that compiles a rego policy from a
// (path, query) flag pair. The helper is the single point used by both
// server (run()) and client (clientBackendDialer()) code paths, so its
// failure modes are not otherwise exercised by serverListen tests.
//
// OPA's file loader supports a "prefix:path" syntax, which means Windows
// absolute paths (C:\...) get mis-parsed (the drive letter is treated as
// the prefix). To keep this test cross-platform we chdir into the temp
// dir and pass relative paths, which contain no ':'.
func TestLoadOPAPolicy(t *testing.T) {
	tempDir := t.TempDir()

	const validName = "valid.rego"
	const garbageName = "garbage.rego"

	if err := os.WriteFile(filepath.Join(tempDir, validName), []byte(`package policy
import input
default allow := true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tempDir, garbageName), []byte(`this is not valid rego`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Chdir(tempDir)

	cases := []struct {
		name       string
		path       string
		query      string
		wantPolicy bool
		wantErr    bool
	}{
		{"both empty disables OPA", "", "", false, false},
		{"only path empty disables OPA", "", "data.policy.allow", false, false},
		{"only query empty disables OPA", validName, "", false, false},
		{"missing file returns error", "nonexistent.rego", "data.policy.allow", false, true},
		{"invalid rego returns error", garbageName, "data.policy.allow", false, true},
		{"valid policy returns non-nil", validName, "data.policy.allow", true, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := loadOPAPolicy(c.path, c.query)
			if c.wantErr {
				assert.Error(t, err)
				assert.Nil(t, p, "policy must be nil when an error is returned")
				return
			}
			assert.NoError(t, err)
			if c.wantPolicy {
				assert.NotNil(t, p, "expected a compiled policy")
			} else {
				assert.Nil(t, p, "expected nil policy (OPA disabled)")
			}
		})
	}
}

// TestSetupMetricsGate pins the metrics-collection gate: live handles bound to
// a registry when at least one sink (--status, --metrics-graphite,
// --metrics-url) is configured, no-op handles and no registry otherwise.
func TestSetupMetricsGate(t *testing.T) {
	// setupMetrics reads package-global flags; save and restore them.
	origStatus, origGraphite, origURL := *statusAddress, *metricsGraphite, *metricsURL
	origPrefix, origInterval, origCA := *metricsPrefix, *metricsInterval, *caBundlePath
	defer func() {
		*statusAddress, *metricsGraphite, *metricsURL = origStatus, origGraphite, origURL
		*metricsPrefix, *metricsInterval, *caBundlePath = origPrefix, origInterval, origCA
	}()

	*metricsPrefix = "ghostunnel"
	*metricsInterval = time.Hour // keep background loops idle during the test
	*metricsGraphite = nil
	*metricsURL = ""
	*caBundlePath = ""

	// No sink configured: collection is skipped entirely.
	*statusAddress = ""
	m, registry, err := setupMetrics()
	assert.NoError(t, err)
	assert.Nil(t, registry, "no sink must mean no registry (collection skipped)")
	assert.NotNil(t, m, "proxy must still get no-op metrics handles")
	m.TotalCounter.Inc(1) // no-op handles must be callable

	// The pull surface alone enables collection, with live handles.
	*statusAddress = "localhost:0"
	m, registry, err = setupMetrics()
	assert.NoError(t, err)
	assert.NotNil(t, registry, "--status must enable metrics collection")
	m.TotalCounter.Inc(1)
	total, ok := registry.SingleValue("accept.total")
	assert.True(t, ok, "live handles must be bound to the returned registry")
	assert.Equal(t, int64(1), total)

	// A push sink alone (no --status) must also enable collection.
	*statusAddress = ""
	*metricsURL = "https://metrics.invalid/post"
	_, registry, err = setupMetrics()
	assert.NoError(t, err)
	assert.NotNil(t, registry, "--metrics-url alone must enable metrics collection")

	// An unreadable CA bundle for the POST client is a startup error.
	*caBundlePath = filepath.Join(t.TempDir(), "missing.pem")
	_, _, err = setupMetrics()
	assert.Error(t, err, "a missing CA bundle must fail setup")
}

// TestSetupMetricsRejectsNonPositiveInterval guards the validation that keeps a
// non-positive --metrics-interval from reaching time.NewTicker (which panics on
// a non-positive duration). The check must only fire when metrics are actually
// collected.
func TestSetupMetricsRejectsNonPositiveInterval(t *testing.T) {
	origStatus, origGraphite, origURL := *statusAddress, *metricsGraphite, *metricsURL
	origInterval := *metricsInterval
	defer func() {
		*statusAddress, *metricsGraphite, *metricsURL = origStatus, origGraphite, origURL
		*metricsInterval = origInterval
	}()

	*metricsGraphite = nil
	*metricsURL = ""

	// A non-positive interval is rejected once a sink makes metrics live.
	*statusAddress = "localhost:0"
	for _, bad := range []time.Duration{0, -1 * time.Second} {
		*metricsInterval = bad
		_, _, err := setupMetrics()
		assert.Error(t, err, "--metrics-interval %s must be rejected", bad)
	}

	// A positive interval is accepted.
	*metricsInterval = 30 * time.Second
	_, registry, err := setupMetrics()
	assert.NoError(t, err, "a positive --metrics-interval must be accepted")
	assert.NotNil(t, registry)

	// When no sink is configured the interval is never used, so a non-positive
	// value must not error (collection is skipped entirely).
	*statusAddress = ""
	*metricsInterval = 0
	_, registry, err = setupMetrics()
	assert.NoError(t, err, "interval is irrelevant when metrics are disabled")
	assert.Nil(t, registry)
}

// TestNewMetricsPostClientHasTimeout pins that the --metrics-url HTTP client is
// built with a timeout (so a hung receiver can't stall the push loop) and a
// TLS 1.2 floor.
func TestNewMetricsPostClientHasTimeout(t *testing.T) {
	client := newMetricsPostClient(nil, 42*time.Second)
	assert.Equal(t, 42*time.Second, client.Timeout, "POST client must bound each request")

	transport, ok := client.Transport.(*http.Transport)
	if assert.True(t, ok, "expected an *http.Transport") {
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
	}
}
