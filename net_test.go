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
	network, address, host, _ := parseUnixOrTCPAddress("unix:/tmp/foo")
	if network != "unix" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "/tmp/foo" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "" {
		t.Errorf("unexpected host: %s", host)
	}

	network, address, host, _ = parseUnixOrTCPAddress("localhost:8080")
	if network != "tcp" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "localhost:8080" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "localhost" {
		t.Errorf("unexpected host: %s", host)
	}

	_, _, _, err := parseUnixOrTCPAddress("localhost")
	assert.NotNil(t, err, "was able to parse invalid host/port")

	_, _, _, err = parseUnixOrTCPAddress("256.256.256.256:99999")
	assert.NotNil(t, err, "was able to parse invalid host/port")
}
