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
		if err != nil {
			panic(err)
		}

		run(wrappedArgs)
	}
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
