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
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func TestLandlockRuleFromStringAddress(t *testing.T) {
	// kind names which of (fs, net) is expected to be non-nil.
	type kind int
	const (
		none    kind = iota // both nil, no error (systemd:/launchd:)
		fsOnly              // FS rule, net nil — unix sockets
		netOnly             // net rule, fs nil — TCP / URL forms
		invalid             // both nil, err non-nil
	)
	testCases := []struct {
		addr string
		want kind
	}{
		{"unix:/tmp/test", fsOnly},
		{"unix:/var/lib/myapp/in.sock", fsOnly}, // non-default path — the regression case
		{"systemd:test", none},
		{"launchd:test", none},
		{"1.2.3.4:5", netOnly},
		{"asdf:50", netOnly},
		{"[1fff:0:a88:85a3::ac1f]:8001", netOnly},
		{"foobar:80", netOnly},
		{"foobar", invalid},
		{"foobar:foobar", invalid},
		{"foobar:100000000000", invalid},
		{"foobar:0", invalid},
		{"http://127.0.0.1:8001/something", netOnly},
		{"https://127.0.0.1:8001/something", netOnly},
		{"http://[1fff:0:a88:85a3::ac1f]:8001/something", netOnly},
		{"https://[1fff:0:a88:85a3::ac1f]:8001/something", netOnly},
		{"http://localhost", netOnly},
		{"https://localhost", netOnly},
		{"http://_:_!", invalid},
		{"https://_:_!", invalid},
		{"http://127.0.0.1:0/something", invalid},
		{"https://127.0.0.1:1000000000/something", invalid},
		{"!", invalid},
		{"", invalid},
	}
	for _, tc := range testCases {
		t.Run(tc.addr, func(t *testing.T) {
			fsRule, netRule, err := ruleFromStringAddress(tc.addr, landlock.ConnectTCP)
			switch tc.want {
			case none:
				if fsRule != nil || netRule != nil || err != nil {
					t.Errorf("want both nil, got fs=%v net=%v err=%v", fsRule, netRule, err)
				}
			case fsOnly:
				if fsRule == nil || netRule != nil || err != nil {
					t.Errorf("want fs rule only, got fs=%v net=%v err=%v", fsRule, netRule, err)
				}
			case netOnly:
				if fsRule != nil || netRule == nil || err != nil {
					t.Errorf("want net rule only, got fs=%v net=%v err=%v", fsRule, netRule, err)
				}
			case invalid:
				if fsRule != nil || netRule != nil {
					t.Errorf("want no rule on invalid input, got fs=%v net=%v", fsRule, netRule)
				}
			}
		})
	}
}

func TestLandlockRulesFromFile(t *testing.T) {
	// Use the canonicalized temp dir so EvalSymlinks comparisons are stable
	// regardless of whether the underlying tempdir contains symlinks.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}

	otherDir := filepath.Join(dir, "other")
	if err := os.Mkdir(otherDir, 0700); err != nil {
		t.Fatal(err)
	}
	symlinkTarget := filepath.Join(otherDir, "target")
	if err := os.WriteFile(symlinkTarget, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(dir, "symlink")
	if err := os.Symlink(symlinkTarget, symlink); err != nil {
		t.Fatal(err)
	}

	testCases := []struct {
		name      string
		path      string
		wantRules int
	}{
		{"regular file", regular, 1},
		{"symlink to other dir", symlink, 2},
		{"non-existent path", filepath.Join(dir, "missing"), 1},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules := rulesFromFile(tc.path)
			if len(rules) != tc.wantRules {
				t.Errorf("got %d rules, want %d", len(rules), tc.wantRules)
			}
		})
	}
}

func TestLandlockRulesFromCertDir(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	// Three symlinks pointing into the same external bundle dir, plus one
	// regular file and one dangling symlink. Expect: 1 rule for dir itself,
	// plus 1 rule per entry whose EvalSymlinks succeeds (3 symlinks + bundle
	// subdir + regular.pem) = 6 rules; landlock dedupes overlapping rules at
	// the kernel level.
	bundleDir := filepath.Join(dir, "bundle")
	if err := os.Mkdir(bundleDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.pem", "b.pem", "c.pem"} {
		target := filepath.Join(bundleDir, name)
		if err := os.WriteFile(target, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, name+".link")); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "regular.pem"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "dangling.link")); err != nil {
		t.Fatal(err)
	}

	rules := rulesFromCertDir(dir)
	// 1 for dir itself + 1 per entry whose EvalSymlinks succeeds: the three
	// .link symlinks, the bundle subdirectory entry, and regular.pem. The
	// dangling symlink is skipped on EvalSymlinks error. Landlock dedupes
	// overlapping rules at the kernel level so we don't bother here.
	if want := 6; len(rules) != want {
		t.Errorf("got %d rules, want %d", len(rules), want)
	}

	t.Run("missing dir", func(t *testing.T) {
		rules := rulesFromCertDir(filepath.Join(dir, "does-not-exist"))
		if want := 1; len(rules) != want {
			t.Errorf("got %d rules, want %d", len(rules), want)
		}
	})
}

func TestLandlockCertmagicDataDir(t *testing.T) {
	testCases := []struct {
		name string
		xdg  string
		home string
		want string
	}{
		{"XDG_DATA_HOME set wins", "/data", "/home/user", "/data/certmagic"},
		{"XDG empty falls back to HOME", "", "/home/user", "/home/user/.local/share/certmagic"},
		{"XDG and HOME both empty falls back to cwd", "", "", ".local/share/certmagic"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tc.xdg)
			t.Setenv("HOME", tc.home)
			if got := certmagicDataDir(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLandlockProxyURLsFromEnv(t *testing.T) {
	testCases := []struct {
		name     string
		env      map[string]string
		wantURLs []string
	}{
		{
			name:     "no env set",
			env:      nil,
			wantURLs: nil,
		},
		{
			name:     "HTTP_PROXY as URL",
			env:      map[string]string{"HTTP_PROXY": "http://proxy.example.com:3128"},
			wantURLs: []string{"http://proxy.example.com:3128"},
		},
		{
			name:     "HTTPS_PROXY as bare host:port",
			env:      map[string]string{"HTTPS_PROXY": "proxy.example.com:8080"},
			wantURLs: []string{"http://proxy.example.com:8080"},
		},
		{
			name:     "HTTPS_PROXY as socks5",
			env:      map[string]string{"HTTPS_PROXY": "socks5://proxy.example.com:1080"},
			wantURLs: []string{"socks5://proxy.example.com:1080"},
		},
		{
			name:     "HTTPS_PROXY as socks5 without port",
			env:      map[string]string{"HTTPS_PROXY": "socks5://proxy.example.com"},
			wantURLs: []string{"socks5://proxy.example.com"},
		},
		{
			name: "upper and lower duplicate dedupe",
			env: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:3128",
				"https_proxy": "http://proxy.example.com:3128",
			},
			wantURLs: []string{"http://proxy.example.com:3128"},
		},
		{
			name: "upper and lower distinct kept",
			env: map[string]string{
				"HTTPS_PROXY": "http://a.example.com:3128",
				"https_proxy": "http://b.example.com:3128",
			},
			wantURLs: []string{"http://a.example.com:3128", "http://b.example.com:3128"},
		},
		{
			name:     "lowercase only",
			env:      map[string]string{"http_proxy": "http://proxy.example.com:3128"},
			wantURLs: []string{"http://proxy.example.com:3128"},
		},
		{
			name:     "HTTP and HTTPS distinct values",
			env:      map[string]string{"HTTP_PROXY": "http://h.example.com:80", "HTTPS_PROXY": "http://s.example.com:443"},
			wantURLs: []string{"http://s.example.com:443", "http://h.example.com:80"},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, name := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
				t.Setenv(name, "")
			}
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			got := proxyURLsFromEnv()
			if len(got) != len(tc.wantURLs) {
				t.Fatalf("got %d URLs %v, want %d %v", len(got), got, len(tc.wantURLs), tc.wantURLs)
			}
			for i, want := range tc.wantURLs {
				if got[i].String() != want {
					t.Errorf("[%d] got %q, want %q", i, got[i].String(), want)
				}
			}
		})
	}
}

func TestLandlockRuleFromURLSocks5DefaultPort(t *testing.T) {
	for _, scheme := range []string{"socks5", "socks5h"} {
		t.Run(scheme, func(t *testing.T) {
			u, err := url.Parse(scheme + "://proxy.example.com")
			if err != nil {
				t.Fatal(err)
			}
			rule, err := ruleFromURL(u, landlock.ConnectTCP)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if rule == nil {
				t.Fatalf("expected rule for %s without explicit port", scheme)
			}
		})
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
		t.Run(tc.addr, func(t *testing.T) {
			rule, _ := ruleFromTCPAddress(net.TCPAddrFromAddrPort(netip.MustParseAddrPort(tc.addr)), landlock.ConnectTCP)
			if tc.valid && rule == nil {
				t.Errorf("no result on valid input")
			}
			if !tc.valid && rule != nil {
				t.Errorf("got result on invalid input")
			}
		})
	}
}
