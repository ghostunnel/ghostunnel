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
	"testing"
	"time"

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

	if isIntegration == "true" {
		var wrappedArgs []string
		err := json.Unmarshal([]byte(os.Getenv("GHOSTUNNEL_INTEGRATION_ARGS")), &wrappedArgs)
		panicOnError(err)

		run(wrappedArgs)
	}
}

func TestInitLoggerSyslog(t *testing.T) {
	*useSyslog = true
	initLogger()
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
	*statusAddr = nil
	err := validateFlags(nil)
	assert.NotNil(t, err, "--enable-pprof implies --status")

	*enableProf = false
	*metricsURL = "127.0.0.1"
	err = validateFlags(nil)
	assert.NotNil(t, err, "invalid --metrics-url should be rejected")
}

func TestServerFlagValidation(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = nil
	*serverAllowedOUs = nil
	*serverAllowedDNSs = nil
	*serverAllowedIPs = nil
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

	*serverAllowAll = false
	*serverUnsafeTarget = false
	*serverForwardAddress = "foo.com"
	err = serverValidateFlags()
	assert.NotNil(t, err, "unsafe target should be rejected")
}

func TestClientFlagValidation(t *testing.T) {
	*clientUnsafeListen = false
	*clientListenAddress = "0.0.0.0:8080"
	err := clientValidateFlags()
	assert.NotNil(t, err, "unsafe listen should be rejected")
}

func TestAllowsLocalhost(t *testing.T) {
	*serverUnsafeTarget = false
	assert.True(t, validateUnixOrLocalhost("localhost:1234"), "localhost should be allowed")
	assert.True(t, validateUnixOrLocalhost("127.0.0.1:1234"), "127.0.0.1 should be allowed")
	assert.True(t, validateUnixOrLocalhost("[::1]:1234"), "[::1] should be allowed")
	assert.True(t, validateUnixOrLocalhost("unix:/tmp/foo"), "unix:/tmp/foo should be allowed")
}

func TestDisallowsFooDotCom(t *testing.T) {
	*serverUnsafeTarget = false
	assert.False(t, validateUnixOrLocalhost("foo.com:1234"), "foo.com should be disallowed")
	assert.False(t, validateUnixOrLocalhost("alocalhost.com:1234"), "alocalhost.com should be disallowed")
	assert.False(t, validateUnixOrLocalhost("localhost.com.foo.com:1234"), "localhost.com.foo.com should be disallowed")
	assert.False(t, validateUnixOrLocalhost("74.122.190.83:1234"), "random ip address should be disallowed")
}

func TestServerBackendDialerError(t *testing.T) {
	*serverForwardAddress = "invalid"
	_, err := serverBackendDialer()
	assert.NotNil(t, err, "invalid forward address should not have dialer")

	*serverForwardAddress = "unix:does-not-exist"
	_, err = serverBackendDialer()
	assert.NotNil(t, err, "invalid forward address should not have dialer")
}

func TestClientBackendDialerError(t *testing.T) {
	*keystorePath = ""
	_, err := clientBackendDialer(nil)
	assert.NotNil(t, err, "cannot create client dialer with invalid keystore")
}

func waitWithTimeout(started chan bool) bool {
	select {
	case up := <-started:
		return up
	case <-time.After(10 * time.Second):
		panic("timed out waiting for channel")
	}
}

func TestClientListenError(t *testing.T) {
	started := make(chan bool, 1)
	*keystorePath = ""
	*statusAddr, _ = net.ResolveTCPAddr("tcp", "127.0.0.1:8080")
	clientListen(started, nil, nil)

	if waitWithTimeout(started) {
		t.Error("client listener should not start with invalid params")
	}

	*statusAddr = nil
	*clientListenAddress = "invalid"
	clientListen(started, nil, nil)

	if waitWithTimeout(started) {
		t.Error("client listener should not start with invalid params")
	}
}
