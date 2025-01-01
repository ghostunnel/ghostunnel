//go:build linux

/*-
 * Copyright 2024, Ghostunnel
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
	"net"
	"net/netip"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func TestLandlockRuleFromStringAddress(t *testing.T) {
	testCases := []struct {
		addr  string
		valid bool
	}{
		{"unix:/tmp/test", true},
		{"systemd:test", false}, // no rule needed
		{"launchd:test", false}, // no rule needed
		{"1.2.3.4:5", true},
		{"asdf:50", true},
		{"[1fff:0:a88:85a3::ac1f]:8001", true},
		{"foobar:80", true},
		{"foobar", false},              // invalid port
		{"foobar:foobar", false},       // invalid port
		{"foobar:100000000000", false}, // invalid port
		{"foobar:0", false},            // invalid port
		{"http://127.0.0.1:8001/something", true},
		{"https://127.0.0.1:8001/something", true},
		{"http://[1fff:0:a88:85a3::ac1f]:8001/something", true},
		{"https://[1fff:0:a88:85a3::ac1f]:8001/something", true},
		{"http://localhost", true},
		{"https://localhost", true},
		{"http://_:_!", false},                            // invalid domain
		{"https://_:_!", false},                           // invalid domain
		{"http://127.0.0.1:0/something", false},           // invalid port
		{"https://127.0.0.1:1000000000/something", false}, // invalid port
		{"!", false},                                      // invalid string
		{"", false},                                       // invalid string
	}
	for _, tc := range testCases {
		rule, _ := ruleFromStringAddress(tc.addr, landlock.ConnectTCP)
		if tc.valid && rule == nil {
			t.Errorf("no result on valid input: %v", tc.addr)
		}
		if !tc.valid && rule != nil {
			t.Errorf("got result on invalid input %s", tc.addr)
		}
	}
}

func TestLandlockRuleFromTCPAddress(t *testing.T) {
	testCases := []struct {
		addr  string
		valid bool
	}{
		{"127.0.0.1:80", true},
		{"127.0.0.1:0", false},
	}
	for _, tc := range testCases {
		rule, _ := ruleFromTCPAddress(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr)), landlock.ConnectTCP)
		if tc.valid && rule == nil {
			t.Errorf("no result on valid input: %v", tc.addr)
		}
		if !tc.valid && rule != nil {
			t.Errorf("got result on invalid input %s", tc.addr)
		}
	}
}
