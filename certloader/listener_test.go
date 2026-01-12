/*-
 * Copyright 2025 Ghostunnel
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

package certloader

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTLSServerConfig implements TLSServerConfig for testing
type mockTLSServerConfig struct {
	config *tls.Config
}

func (m *mockTLSServerConfig) GetServerConfig() *tls.Config {
	return m.config
}

// failingListener is a mock listener that always fails on Accept
type failingListener struct{}

func (f *failingListener) Accept() (net.Conn, error) {
	return nil, errors.New("mock accept error")
}

func (f *failingListener) Close() error {
	return nil
}

func (f *failingListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}

func TestNewListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer inner.Close()

	mockConfig := &mockTLSServerConfig{config: &tls.Config{}}
	listener := NewListener(inner, mockConfig)

	assert.Equal(t, inner.Addr(), listener.Addr())
	assert.Equal(t, inner, listener.Listener)
}

func TestListenerAccept(t *testing.T) {
	// Create test certificates
	_, serverCert := spiffetest.CreateWebCredentials(t)

	// Create inner TCP listener
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Create TLS config
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	}
	mockConfig := &mockTLSServerConfig{config: serverConfig}
	listener := NewListener(inner, mockConfig)
	defer listener.Close()

	// Accept in goroutine (server side)
	acceptDone := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		// Complete handshake on server side
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			acceptErr <- err
			return
		}
		acceptDone <- conn
	}()

	// Connect from client side
	clientConn, err := tls.Dial("tcp", listener.Addr().String(),
		&tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	defer clientConn.Close()

	// Wait for server to accept
	select {
	case conn := <-acceptDone:
		defer conn.Close()
		// Verify it's a TLS connection
		_, ok := conn.(*tls.Conn)
		assert.True(t, ok, "returned connection should be TLS")
	case err := <-acceptErr:
		t.Fatalf("accept failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("test timed out")
	}
}

func TestListenerAcceptError(t *testing.T) {
	// Test error propagation when inner listener fails
	mockListener := &failingListener{}
	mockConfig := &mockTLSServerConfig{config: &tls.Config{}}
	listener := NewListener(mockListener, mockConfig)

	_, err := listener.Accept()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mock accept error")
}

func TestListenerClose(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mockConfig := &mockTLSServerConfig{config: &tls.Config{}}
	listener := NewListener(inner, mockConfig)

	// Close should close the inner listener
	err = listener.Close()
	assert.NoError(t, err)

	// Trying to accept should fail now
	_, err = inner.Accept()
	assert.Error(t, err)
}

func TestListenerConfigReload(t *testing.T) {
	// Create test certificates
	_, serverCert1 := spiffetest.CreateWebCredentials(t)
	_, serverCert2 := spiffetest.CreateWebCredentials(t)

	// Create inner TCP listener
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	// Start with first config
	currentConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert1},
	}

	// Create a mock config that can be updated
	mockConfig := &reloadableMockConfig{config: currentConfig}
	listener := NewListener(inner, mockConfig)
	defer listener.Close()

	// Helper to do one connection cycle
	doConnection := func() error {
		acceptDone := make(chan net.Conn, 1)
		acceptErr := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				acceptErr <- err
				return
			}
			// Complete handshake
			tlsConn := conn.(*tls.Conn)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				acceptErr <- err
				return
			}
			acceptDone <- conn
		}()

		// Connect from client
		clientConn, err := tls.Dial("tcp", listener.Addr().String(),
			&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
		clientConn.Close()

		select {
		case conn := <-acceptDone:
			conn.Close()
			return nil
		case err := <-acceptErr:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("timeout")
		}
	}

	// First connection with first config
	err = doConnection()
	require.NoError(t, err)

	// Update config (simulating reload)
	mockConfig.config = &tls.Config{
		Certificates: []tls.Certificate{*serverCert2},
	}

	// Second connection should use new config
	err = doConnection()
	require.NoError(t, err)
}

// reloadableMockConfig allows config changes between accepts
type reloadableMockConfig struct {
	config *tls.Config
}

func (m *reloadableMockConfig) GetServerConfig() *tls.Config {
	return m.config
}
