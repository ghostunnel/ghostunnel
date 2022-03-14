/*-
 * Copyright 2019 Square Inc.
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

package socket

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAddress(t *testing.T) {
	network, address, host, _ := ParseAddress("unix:/tmp/foo", false)
	if network != "unix" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "/tmp/foo" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "" {
		t.Errorf("unexpected host: %s", host)
	}

	network, address, host, _ = ParseAddress("localhost:8080", false)
	if network != "tcp" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "localhost:8080" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "localhost" {
		t.Errorf("unexpected host: %s", host)
	}

	network, address, host, _ = ParseAddress("launchd:listener", false)
	if network != "launchd" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "listener" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "" {
		t.Errorf("unexpected host: %s", host)
	}

	network, address, host, _ = ParseAddress("systemd:test", false)
	if network != "systemd" {
		t.Errorf("unexpected network: %s", network)
	}
	if address != "test" {
		t.Errorf("unexpected address: %s", address)
	}
	if host != "" {
		t.Errorf("unexpected host: %s", host)
	}

	_, _, _, err := ParseAddress("localhost", false)
	assert.NotNil(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("256.256.256.256:99999", false)
	assert.NotNil(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("launchdfoobar", false)
	assert.NotNil(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("systemdfoobar", false)
	assert.NotNil(t, err, "was able to parse invalid host/port")
}

func TestParseHTTPAddress(t *testing.T) {
	https, address := ParseHTTPAddress("http://localhost")
	if https != false {
		t.Errorf("unexpected https: %t", https)
	}
	if address != "localhost" {
		t.Errorf("unexpected address: %s", address)
	}

	https, address = ParseHTTPAddress("https://localhost")
	if https != true {
		t.Errorf("unexpected https: %t", https)
	}
	if address != "localhost" {
		t.Errorf("unexpected address: %s", address)
	}

	https, address = ParseHTTPAddress("127.0.0.1:8000")
	if https != true {
		t.Errorf("unexpected https: %t", https)
	}
	if address != "127.0.0.1:8000" {
		t.Errorf("unexpected address: %s", address)
	}
}
