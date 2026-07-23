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
	"os"
	"path/filepath"
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
	assert.Error(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("256.256.256.256:99999", false)
	assert.Error(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("launchdfoobar", false)
	assert.Error(t, err, "was able to parse invalid host/port")

	_, _, _, err = ParseAddress("systemdfoobar", false)
	assert.Error(t, err, "was able to parse invalid host/port")
}

func TestIsDialableNetwork(t *testing.T) {
	assert.True(t, IsDialableNetwork("tcp"), "tcp must be dialable")
	assert.True(t, IsDialableNetwork("unix"), "unix must be dialable")
	assert.False(t, IsDialableNetwork("systemd"), "systemd is listen-only")
	assert.False(t, IsDialableNetwork("launchd"), "launchd is listen-only")
	assert.False(t, IsDialableNetwork(""), "empty network must not be dialable")
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

func TestOpenTCPSocket(t *testing.T) {
	ln, err := Open("tcp", "127.0.0.1:0")
	assert.NoError(t, err, "should be able to open TCP socket on random port")
	defer func() { _ = ln.Close() }()
	assert.NotNil(t, ln.Addr(), "listener should have an address")
}

func TestOpenUnixSocket(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	ln, err := Open("unix", sockPath)
	assert.NoError(t, err, "should be able to open Unix socket")
	defer func() { _ = ln.Close() }()
	assert.NotNil(t, ln.Addr(), "listener should have an address")
}

// TestOpenUnixSocketUnlinksOnClose pins down the contract that callers
// (clientListen, serverListen) rely on: when Open creates a UNIX socket on
// behalf of ghostunnel, it owns the path and unlinks it on Close. If this
// guarantee is removed, the redundant cleanup that used to live in
// clientListen would need to be restored.
func TestOpenUnixSocketUnlinksOnClose(t *testing.T) {
	// Use a short tmpdir to stay under macOS's 104-char sun_path limit.
	tmpDir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(tmpDir) })
	sockPath := filepath.Join(tmpDir, "test.sock")

	ln, err := Open("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sockPath); err != nil {
		t.Fatalf("socket should exist after Open: %v", err)
	}

	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = os.Stat(sockPath)
	assert.True(t, os.IsNotExist(err), "socket should be unlinked after Close, but got: %v", err)
}

func TestOpenUnixSocketListenError(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "missing", "test.sock")
	ln, err := Open("unix", sockPath)
	assert.Error(t, err, "should fail to open Unix socket under non-existent directory")
	assert.Nil(t, ln, "listener should be nil on error")
	if ln != nil {
		_ = ln.Close()
	}
}

func TestParseAndOpenTCPSuccess(t *testing.T) {
	ln, err := ParseAndOpen("127.0.0.1:0")
	assert.NoError(t, err, "should be able to parse and open TCP address")
	defer func() { _ = ln.Close() }()
}

func TestParseAndOpenUnixSuccess(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "test.sock")
	ln, err := ParseAndOpen("unix:" + sockPath)
	assert.NoError(t, err, "should be able to parse and open Unix socket")
	defer func() { _ = ln.Close() }()
}

func TestParseAndOpenInvalidAddress(t *testing.T) {
	_, err := ParseAndOpen("invalid-no-port")
	assert.Error(t, err, "should fail to parse invalid address")
}

func TestParseAndOpenUnresolvable(t *testing.T) {
	_, err := ParseAndOpen("nonexistent.invalid.domain.test:8080")
	assert.Error(t, err, "should fail to resolve nonexistent domain")
}

func TestParseAddressWithSkipResolve(t *testing.T) {
	// With skipResolve=true, should not fail on unresolvable address
	network, address, host, err := ParseAddress("nonexistent.invalid.domain.test:8080", true)
	assert.NoError(t, err, "should succeed with skipResolve=true")
	assert.Equal(t, "tcp", network)
	assert.Equal(t, "nonexistent.invalid.domain.test:8080", address)
	assert.Equal(t, "nonexistent.invalid.domain.test", host)
}
