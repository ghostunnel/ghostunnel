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
  "fmt"
	"testing"
)

func TestParseUnixOrTcpAddress(t *testing.T) {
	network, address, host, _ := parseUnixOrTcpAddress("unix:/tmp/foo")
	if network != "unix" {
		t.Error(fmt.Sprintf("unexpected network: %s", network))
	}
	if address != "/tmp/foo" {
		t.Error(fmt.Sprintf("unexpected address: %s", address))
	}
	if host != "" {
		t.Error(fmt.Sprintf("unexpected host: %s", host))
	}

	network, address, host, _ = parseUnixOrTcpAddress("localhost:8080")
	// note: ipv6 test is proabably fragile, we don't expand ::1.
	if network != "tcp4" && network != "tcp6" {
		t.Error(fmt.Sprintf("unexpected network: %s", network))
	}
	if address != "127.0.0.1:8080" && address != "[::1]:8080" {
		t.Error(fmt.Sprintf("unexpected address: %s", address))
	}
	if host != "localhost" {
		t.Error(fmt.Sprintf("unexpected host: %s", host))
	}
}
