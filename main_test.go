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
	"errors"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
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

	// Test: --proxy-protocol and --proxy-protocol-mode are mutually exclusive
	*keystorePath = "file"
	*serverAllowAll = true
	*serverProxyProtocol = true
	*serverProxyProtocolMode = "tls"
	err = serverValidateFlags()
	assert.NotNil(t, err, "--proxy-protocol and --proxy-protocol-mode are mutually exclusive")

	// Test: --proxy-protocol-mode alone is valid
	*serverProxyProtocol = false
	*serverProxyProtocolMode = "tls"
	err = serverValidateFlags()
	assert.Nil(t, err, "--proxy-protocol-mode alone should be valid")
	*serverProxyProtocol = false
	*serverProxyProtocolMode = ""
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

	// Test: OPA flags must be used together
	*keystorePath = "file"
	*clientListenAddress = "127.0.0.1:8080"
	*enabledCipherSuites = "AES,CHACHA"

	*clientAllowPolicy = "policy"
	*clientAllowQuery = ""
	err = clientValidateFlags()
	assert.NotNil(t, err, "--verify-policy needs --verify-query")

	*clientAllowPolicy = ""
	*clientAllowQuery = "query"
	err = clientValidateFlags()
	assert.NotNil(t, err, "--verify-query needs --verify-policy")

	*clientAllowPolicy = "policy"
	*clientAllowQuery = "query"
	err = clientValidateFlags()
	assert.Nil(t, err, "--verify-policy and --verify-query together should be valid")

	*clientAllowPolicy = ""
	*clientAllowQuery = ""
	err = clientValidateFlags()
	assert.Nil(t, err, "neither OPA flag set should be valid")
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
	err := validateServerOPA(false, false)
	assert.Nil(t, err, "validateServerOPA must return nil when no OPA flags are set")

	err = validateServerOPA(true, false)
	assert.Nil(t, err, "validateServerOPA must return nil when OPA disabled even if access flags set")
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

// TestCheckBackendStatusInvalidURLNonStatus is intentionally absent — the
// equivalent test is in status_test.go (TestCheckBackendStatusInvalidURL).
//
// TestSignalHandlerReloadAndShutdown lives in unix_test.go because it relies
// on POSIX signal delivery (SIGHUP) which is unavailable on Windows.

// TestServerListenEarlyErrors covers three early-return failure paths in
// serverListen that occur before any listener is opened:
//  1. buildServerConfig fails on a bad cipher suite.
//  2. wildcard.CompileList fails on an invalid URI pattern.
//  3. policy.LoadFromPath fails on a missing rego file.
//
// All three return before serverListen dereferences env, so a zero-value
// *Environment is sufficient.
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
		{
			name: "policy load fails",
			setup: func() {
				*enabledCipherSuites = "AES,CHACHA"
				*maxTLSVersion = ""
				*serverAllowedURIs = nil
				*serverAllowPolicy = "/nonexistent.rego"
				*serverAllowQuery = "data.policy.allow"
				*serverAllowAll = false
			},
			wantSubstr: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.setup()
			env := &Environment{}
			err := serverListen(env)
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
		name           string
		hasAccessFlags bool
		hasOPAFlags    bool
		policy, query  string
		wantErrSubstr  string // "" means expect nil
	}{
		{"no flags", false, false, "", "", ""},
		{"access only", true, false, "", "", ""},
		{"OPA only - missing query", false, true, "policy", "", "have to be used together"},
		{"OPA only - missing policy", false, true, "", "query", "have to be used together"},
		{"both OPA and access", true, true, "policy", "query", "mutually exclusive"},
		{"OPA only - both set", false, true, "policy", "query", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			*serverAllowPolicy = c.policy
			*serverAllowQuery = c.query

			err := validateServerOPA(c.hasAccessFlags, c.hasOPAFlags)
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
