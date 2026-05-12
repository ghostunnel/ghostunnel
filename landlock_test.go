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
	"reflect"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func TestLandlockRuleFromStringAddressConnect(t *testing.T) {
	testCases := []struct {
		name    string
		addr    string
		want    landlock.Rule
		wantErr bool
	}{
		{"unix socket", "unix:/tmp/test", landlock.RWFiles("/tmp/test"), false},
		{"unix triple slash (SPIFFE)", "unix:///path/to/endpoint.sock", landlock.RWFiles("/path/to/endpoint.sock"), false},
		{"systemd activation", "systemd:test", nil, false},
		{"launchd activation", "launchd:test", nil, false},
		{"tcp scheme (SPIFFE)", "tcp://127.0.0.1:8000", landlock.ConnectTCP(8000), false},
		{"ipv4 host:port", "1.2.3.4:5", landlock.ConnectTCP(5), false},
		{"hostname host:port", "asdf:50", landlock.ConnectTCP(50), false},
		{"ipv6 host:port", "[1fff:0:a88:85a3::ac1f]:8001", landlock.ConnectTCP(8001), false},
		{"hostname:port", "foobar:80", landlock.ConnectTCP(80), false},
		{"missing port", "foobar", nil, true},
		{"non-numeric port", "foobar:foobar", nil, true},
		{"port too large", "foobar:100000000000", nil, true},
		{"port zero", "foobar:0", nil, true},
		{"http ipv4 explicit port", "http://127.0.0.1:8001/something", landlock.ConnectTCP(8001), false},
		{"https ipv4 explicit port", "https://127.0.0.1:8001/something", landlock.ConnectTCP(8001), false},
		{"http ipv6 explicit port", "http://[1fff:0:a88:85a3::ac1f]:8001/something", landlock.ConnectTCP(8001), false},
		{"https ipv6 explicit port", "https://[1fff:0:a88:85a3::ac1f]:8001/something", landlock.ConnectTCP(8001), false},
		{"http default port", "http://localhost", landlock.ConnectTCP(80), false},
		{"https default port", "https://localhost", landlock.ConnectTCP(443), false},
		{"http invalid domain", "http://_:_!", nil, true},
		{"https invalid domain", "https://_:_!", nil, true},
		{"http port zero", "http://127.0.0.1:0/something", nil, true},
		{"https port too large", "https://127.0.0.1:1000000000/something", nil, true},
		{"garbage", "!", nil, true},
		{"empty string", "", nil, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ruleFromStringAddress(tc.addr, landlock.ConnectTCP)
			checkRule(t, tc.addr, rule, err, tc.want, tc.wantErr)
		})
	}
}

func TestLandlockRuleFromStringAddressBind(t *testing.T) {
	testCases := []struct {
		name    string
		addr    string
		want    landlock.Rule
		wantErr bool
	}{
		{"unix socket", "unix:/tmp/test", landlock.RWFiles("/tmp/test"), false},
		{"unix triple slash", "unix:///var/run/foo.sock", landlock.RWFiles("/var/run/foo.sock"), false},
		{"systemd activation", "systemd:test", nil, false},
		{"launchd activation", "launchd:test", nil, false},
		{"ipv4 host:port", "1.2.3.4:5", landlock.BindTCP(5), false},
		{"ipv6 host:port", "[1fff:0:a88:85a3::ac1f]:8001", landlock.BindTCP(8001), false},
		{"hostname:port", "foobar:80", landlock.BindTCP(80), false},
		{"missing port", "foobar", nil, true},
		{"port zero", "foobar:0", nil, true},
		{"http default port", "http://localhost", landlock.BindTCP(80), false},
		{"https default port", "https://localhost", landlock.BindTCP(443), false},
		{"http explicit port", "http://127.0.0.1:8001/something", landlock.BindTCP(8001), false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ruleFromStringAddress(tc.addr, landlock.BindTCP)
			checkRule(t, tc.addr, rule, err, tc.want, tc.wantErr)
		})
	}
}

func TestLandlockRuleFromTCPAddressConnect(t *testing.T) {
	testCases := []struct {
		name    string
		addr    string
		want    landlock.Rule
		wantErr bool
	}{
		{"ipv4", "127.0.0.1:80", landlock.ConnectTCP(80), false},
		{"port zero", "127.0.0.1:0", nil, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ruleFromTCPAddress(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr)), landlock.ConnectTCP)
			checkRule(t, tc.addr, rule, err, tc.want, tc.wantErr)
		})
	}
}

func TestLandlockRuleFromTCPAddressBind(t *testing.T) {
	testCases := []struct {
		name    string
		addr    string
		want    landlock.Rule
		wantErr bool
	}{
		{"ipv4", "127.0.0.1:80", landlock.BindTCP(80), false},
		{"port zero", "127.0.0.1:0", nil, true},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := ruleFromTCPAddress(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr)), landlock.BindTCP)
			checkRule(t, tc.addr, rule, err, tc.want, tc.wantErr)
		})
	}
}

func checkRule(t *testing.T, addr string, got landlock.Rule, gotErr error, want landlock.Rule, wantErr bool) {
	t.Helper()
	if wantErr && gotErr == nil {
		t.Errorf("expected error for input %q, got rule %v", addr, got)
	}
	if !wantErr && gotErr != nil {
		t.Errorf("unexpected error for input %q: %v", addr, gotErr)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rule mismatch for input %q:\n  got:  %v\n  want: %v", addr, got, want)
	}
}
