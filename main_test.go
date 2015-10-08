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

func TestAllowsAllTargets(t *testing.T) {
	*unsafeTarget = true
	assert.True(t, validateTarget("foo.com:1234"), "foo.com should be allowed")
}

func TestAllowsLocalhost(t *testing.T) {
	*unsafeTarget = false
	assert.True(t, validateTarget("localhost:1234"), "localhost should be allowed")
	assert.True(t, validateTarget("127.0.0.1:1234"), "127.0.0.1 should be allowed")
	assert.True(t, validateTarget("[::1]:1234"), "[::1] should be allowed")
}

func TestDisallowsFooDotCom(t *testing.T) {
	*unsafeTarget = false
	assert.False(t, validateTarget("foo.com:1234"), "foo.com should be disallowed")
	assert.False(t, validateTarget("alocalhost.com:1234"), "alocalhost.com should be disallowed")
	assert.False(t, validateTarget("74.122.190.83:1234"), "random ip address should be disallowed")
}
