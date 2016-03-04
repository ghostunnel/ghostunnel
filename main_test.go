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
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntegrationMain(t *testing.T) {
	// This function serves as an entry point for running integration tests.
	// We're wrapping it in a test case so that we can record the test coverage.
	isIntegration := os.Getenv("GHOSTUNNEL_INTEGRATION_TEST")

	if isIntegration == "true" {
		var wrappedArgs []string
		err := json.Unmarshal([]byte(os.Getenv("GHOSTUNNEL_INTEGRATION_ARGS")), &wrappedArgs)
		panicOnError(err)

		run(wrappedArgs)
	}
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
