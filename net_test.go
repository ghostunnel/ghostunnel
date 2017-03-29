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

func TestParseUnixOrTcpAddress(t *testing.T) {
	addr, _ := parseUnixOrTCPAddress("unix:/tmp/foo")
	if addr.network != "unix" {
		t.Errorf("unexpected network: %s", addr.network)
	}
	if addr.address != "/tmp/foo" {
		t.Errorf("unexpected address: %s", addr.address)
	}
	if addr.host != "" {
		t.Errorf("unexpected host: %s", addr.host)
	}

	addr, _ = parseUnixOrTCPAddress("localhost:8080")
	// note: ipv6 test is probably fragile, we don't expand ::1.
	if addr.network != "tcp" {
		t.Errorf("unexpected network: %s", addr.network)
	}
	if addr.address != "127.0.0.1:8080" && addr.address != "[::1]:8080" {
		t.Errorf("unexpected address: %s", addr.address)
	}
	if addr.host != "localhost" {
		t.Errorf("unexpected host: %s", addr.host)
	}

	_, err := parseUnixOrTCPAddress("localhost")
	assert.NotNil(t, err, "was able to parse invalid host/port")

	_, err = parseUnixOrTCPAddress("256.256.256.256:99999")
	assert.NotNil(t, err, "was able to parse invalid host/port")
}
