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
	"encoding/json"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
	"github.com/stretchr/testify/assert"
)

func TestIntegrationMain(t *testing.T) {
	// This function serves as an entry point for running integration tests.
	// We're wrapping it in a test case so that we can record the test coverage.
	isIntegration := os.Getenv("GHOSTUNNEL_INTEGRATION_TEST")

	// Catch panics to make sure test exits normally and writes coverage
	// even if we got a crash (we might want to test error cases)
	defer func() {
		if err := recover(); err != nil {
			t.Error(err)
		}
	}()

	if isIntegration != "true" {
		t.Skip("skipping, not an integration test")
		return
	}

	execPath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	addLandlockTestPaths([]string{path.Join(filepath.Dir(execPath), "coverage")})

	finished := make(chan bool, 1)
	once := &sync.Once{}

	// override exit function for test, to make sure calls to exitFunc() don't
	// actually terminate the process and kill the test w/o capturing results.
	exitFunc = func(exit int) {
		once.Do(func() {
			if exit != 0 {
				t.Errorf("exit code from ghostunnel: %d", exit)
			}
		})
		finished <- true
		select {} // block
	}

	var wrappedArgs []string
	err = json.Unmarshal([]byte(os.Getenv("GHOSTUNNEL_INTEGRATION_ARGS")), &wrappedArgs)
	panicOnError(err)

	go func() {
		err := run(wrappedArgs)
		if err != nil {
			t.Errorf("got error from run: %s", err)
		}
		finished <- true
	}()

	select {
	case <-finished:
		return
	case <-time.Tick(10 * time.Minute):
		panic("timed out")
	}
}

func TestInitLoggerQuiet(t *testing.T) {
	originalLogger := logger
	err := initLogger(false, []string{"all"})
	assert.Nil(t, err)

	updatedLogger := logger
	assert.NotEqual(t, originalLogger, updatedLogger, "should have updated logger object")
	assert.NotNil(t, logger, "logger should never be nil after init")
}

func TestInitLoggerSyslog(t *testing.T) {
	originalLogger := logger
	err := initLogger(true, []string{})
	updatedLogger := logger
	if err != nil {
		// Tests running in containers often don't have access to syslog,
		// so we can't depend on syslog being available for testing. If we
		// get an error from the syslog setup we just warn and skip test.
		t.Logf("Error setting up syslog for test, skipping: %s", err)
		t.SkipNow()
		return
	}
	assert.NotEqual(t, originalLogger, updatedLogger, "should have updated logger object")
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
	*enableProf = true
	*statusAddress = ""
	err := validateFlags(nil)
	assert.NotNil(t, err, "--enable-pprof implies --status")

	*enableProf = false
	*metricsURL = "127.0.0.1"
	err = validateFlags(nil)
	assert.NotNil(t, err, "invalid --metrics-url should be rejected")
	*metricsURL = ""

	*enableProf = false
	*serverStatusTargetAddress = "127.0.0.1:8000"
	err = validateFlags(nil)
	assert.NotNil(t, err, "--target-status should start with http:// or https://")
	*serverStatusTargetAddress = ""

	*connectTimeout = 0
	err = validateFlags(nil)
	assert.NotNil(t, err, "invalid --connect-timeout should be rejected")
	*connectTimeout = 10 * time.Second
}

func TestServerFlagValidation(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = nil
	*serverAllowedOUs = nil
	*serverAllowedDNSs = nil
	*serverAllowedIPs = nil
	*serverAllowedURIs = nil
	err := serverValidateFlags()
	assert.NotNil(t, err, "invalid access control flags accepted")

	*serverAllowAll = true
	*serverAllowedCNs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-cn are mutually exclusive")

	*serverAllowedCNs = nil
	*serverAllowedOUs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-ou are mutually exclusive")

	*serverAllowedOUs = nil
	*serverAllowedDNSs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-dns-san are mutually exclusive")

	*serverAllowedDNSs = nil
	*serverAllowedIPs = []net.IP{net.IPv4(0, 0, 0, 0)}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-ip-san are mutually exclusive")

	// OPA flags
	*serverAllowedIPs = nil
	*serverAllowPolicy = "policy"
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-policy are mutually exclusive")

	*serverAllowPolicy = ""
	*serverAllowQuery = "query"
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all and --allow-query are mutually exclusive")

	*serverAllowAll = false
	*serverAllowPolicy = "policy"
	*serverAllowQuery = ""
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy needs --allow-query")

	*serverAllowPolicy = ""
	*serverAllowQuery = "query"
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-query needs --allow-policy")

	*serverAllowPolicy = "policy"
	*serverAllowQuery = "query"
	*serverAllowedCNs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy and --allow-cn are mutually exclusive")

	*serverAllowedCNs = nil
	*serverAllowedOUs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy and --allow-ou are mutually exclusive")

	*serverAllowedOUs = nil
	*serverAllowedDNSs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy and --allow-dns-san are mutually exclusive")

	*serverAllowedDNSs = nil
	*serverAllowedIPs = []net.IP{net.IPv4(0, 0, 0, 0)}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy and --allow-ip-san are mutually exclusive")

	*serverAllowedIPs = nil
	*serverAllowAll = true
	*serverDisableAuth = true
	err = serverValidateFlags()
	assert.NotNil(t, err, "--disable-authentication mutually exclusive with --allow-all and other server access control flags")

	*serverAllowedCNs = nil
	*serverAllowAll = true
	*serverDisableAuth = true
	err = serverValidateFlags()
	assert.NotNil(t, err, "--disable-authentication mutually exclusive with --allow-all and other server access control flags")

	*keystorePath = "file"
	*serverAllowedCNs = []string{"test"}
	*serverDisableAuth = false
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-all mutually exclusive with other access control flags")
	*serverAllowedCNs = nil

	*serverAllowAll = false
	*serverUnsafeTarget = false
	*serverForwardAddress = "foo.com"
	err = serverValidateFlags()
	assert.NotNil(t, err, "unsafe target should be rejected")

	*certPath = "file"
	err = serverValidateFlags()
	assert.NotNil(t, err, "--cert also requires --key or should error")
	*certPath = ""

	test := "test"
	*keystorePath = "file"
	keychainIdentity = &test
	err = serverValidateFlags()
	assert.NotNil(t, err, "--keystore and --keychain-identity can't be set at the same time")

	keychainIdentity = nil
	keychainIssuer = &test
	err = serverValidateFlags()
	assert.NotNil(t, err, "--keystore and --keychain-issuer can't be set at the same time")

	*keystorePath = ""
	*certPath = "file"
	*keyPath = "file"
	keychainIdentity = &test
	err = serverValidateFlags()
	assert.NotNil(t, err, "--cert and --keychain-identity/issuer can't be set at the same time")
	*certPath = ""
	*keyPath = ""
	keychainIdentity = nil
	keychainIssuer = nil

	*keystorePath = "test"
	*serverDisableAuth = true
	*serverAllowAll = true
	err = serverValidateFlags()
	assert.NotNil(t, err, "can't use access control flags if auth is disabled")
	*serverDisableAuth = false

	*serverForwardAddress = "example.com:443"
	err = serverValidateFlags()
	assert.NotNil(t, err, "should reject non-local address if unsafe flag not set")

	*enabledCipherSuites = "ABC"
	*serverForwardAddress = "127.0.0.1:8080"
	err = serverValidateFlags()
	assert.NotNil(t, err, "invalid cipher suite option should be rejected")

	*enabledCipherSuites = "AES,CHACHA"
	*serverForwardAddress = ""
	*serverAllowAll = false
	*keystorePath = ""
}

func TestClientFlagValidation(t *testing.T) {
	*keystorePath = "file"
	*clientUnsafeListen = false
	*clientListenAddress = "0.0.0.0:8080"
	err := clientValidateFlags()
	assert.NotNil(t, err, "unsafe listen should be rejected")

	*clientDisableAuth = true
	err = clientValidateFlags()
	assert.NotNil(t, err, "--keystore can't be used with --disable-authentication")

	*keystorePath = ""
	*certPath = "file"
	*keyPath = "file"
	err = clientValidateFlags()
	assert.NotNil(t, err, "--cert/--key can't be used with --disable-authentication")

	*keystorePath = "file"
	*certPath = "file"
	*keyPath = "file"
	*clientDisableAuth = false
	err = clientValidateFlags()
	assert.NotNil(t, err, "--keystore can't be used with --cert/--key")
	*certPath = ""
	*keyPath = ""

	test := "test"
	keychainIdentity = &test
	err = clientValidateFlags()
	assert.NotNil(t, err, "--keystore can't be used with --keychain-identity")
	keychainIdentity = nil

	*enabledCipherSuites = "ABC"
	*clientListenAddress = "127.0.0.1:8080"
	err = clientValidateFlags()
	assert.NotNil(t, err, "invalid cipher suite option should be rejected")

	*clientDisableAuth = false
	*keystorePath = ""
	err = clientValidateFlags()
	assert.NotNil(t, err, "one of --keystore or --disable-authentication is required")
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
	*serverForwardAddress = "invalid"
	_, err := serverBackendDialer()
	assert.NotNil(t, err, "invalid forward address should not have dialer")
}

func TestInvalidCABundle(t *testing.T) {
	err := run([]string{
		"server",
		"--cacert", "/dev/null",
		"--target", "localhost:8080",
		"--keystore", "keystore.p12",
		"--listen", "localhost:8080",
	})
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
