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
	"encoding/json"
	"errors"
	"net"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/certloader"
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
	*enableShutdown = true
	*statusAddress = ""
	err = validateFlags(nil)
	assert.NotNil(t, err, "--enable-shutdown implies --status")
	*enableShutdown = false
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

	// Test: no credentials at all
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""
	*useWorkloadAPI = false
	*serverAutoACMEFQDN = ""
	keychainIdentity = nil
	keychainIssuer = nil
	*serverAllowAll = true
	*serverForwardAddress = "127.0.0.1:8080"
	err = serverValidateFlags()
	assert.NotNil(t, err, "should require at least one credential source")
	assert.Contains(t, err.Error(), "at least one of")

	// Test: --key without --cert
	*keystorePath = ""
	*keyPath = "file"
	*certPath = ""
	err = serverValidateFlags()
	assert.NotNil(t, err, "--key without --cert should be rejected")
	*keyPath = ""

	// Test: --disable-authentication with --allow-cn (not --allow-all)
	*keystorePath = "file"
	*serverDisableAuth = true
	*serverAllowAll = false
	*serverAllowedCNs = []string{"test"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--disable-authentication is mutually exclusive with --allow-cn")
	*serverAllowedCNs = nil
	*serverDisableAuth = false

	// Test: OPA flags with --allow-uri
	*serverAllowPolicy = "policy"
	*serverAllowQuery = "query"
	*serverAllowedURIs = []string{"spiffe://example.com/*"}
	err = serverValidateFlags()
	assert.NotNil(t, err, "--allow-policy and --allow-uri are mutually exclusive")
	*serverAllowPolicy = ""
	*serverAllowQuery = ""
	*serverAllowedURIs = nil
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

	// Test: --cert without --key
	*enabledCipherSuites = "AES,CHACHA"
	*certPath = "file"
	*keyPath = ""
	*clientListenAddress = "127.0.0.1:8080"
	err = clientValidateFlags()
	assert.NotNil(t, err, "--cert without --key should be rejected")
	*certPath = ""

	// Test: --key without --cert
	*keyPath = "file"
	*certPath = ""
	err = clientValidateFlags()
	assert.NotNil(t, err, "--key without --cert should be rejected")
	*keyPath = ""
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
	cmd := []string{
		"server",
		"--cacert", "/dev/null",
		"--target", "localhost:8080",
		"--keystore", "keystore.p12",
		"--listen", "localhost:8080",
	}
	if runtime.GOOS == "linux" {
		// Disable landlock so we don't inadvertendly affect later unit tests.
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

func TestMustGetServerConfigPanicsOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when GetServerConfig fails")
		}
	}()

	source := &failingTLSConfigSource{}
	mustGetServerConfig(source, nil)
}

func TestMustGetClientConfigPanicsOnError(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic when GetClientConfig fails")
		}
	}()

	source := &failingTLSConfigSource{}
	mustGetClientConfig(source, nil)
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
	origKeystorePath := *keystorePath
	origCertPath := *certPath
	origKeyPath := *keyPath
	origCaBundlePath := *caBundlePath
	origUseWorkloadAPI := *useWorkloadAPI
	origServerAutoACMEFQDN := *serverAutoACMEFQDN
	origServerAutoACMEEmail := *serverAutoACMEEmail
	origServerAutoACMEAgreedTOS := *serverAutoACMEAgreedTOS
	origServerAutoACMETestCA := *serverAutoACMETestCA
	defer func() {
		*keystorePath = origKeystorePath
		*certPath = origCertPath
		*keyPath = origKeyPath
		*caBundlePath = origCaBundlePath
		*useWorkloadAPI = origUseWorkloadAPI
		*serverAutoACMEFQDN = origServerAutoACMEFQDN
		*serverAutoACMEEmail = origServerAutoACMEEmail
		*serverAutoACMEAgreedTOS = origServerAutoACMEAgreedTOS
		*serverAutoACMETestCA = origServerAutoACMETestCA
	}()

	*useWorkloadAPI = false
	*serverAutoACMEFQDN = "test.example.com"
	*serverAutoACMEEmail = "test@example.com"
	*serverAutoACMEAgreedTOS = true
	*serverAutoACMETestCA = "https://127.0.0.1:1/directory"
	*keystorePath = ""
	*certPath = ""
	*keyPath = ""

	_, err := getTLSConfigSource(false)
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
