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
	"testing"

	"github.com/stretchr/testify/assert"
)

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
