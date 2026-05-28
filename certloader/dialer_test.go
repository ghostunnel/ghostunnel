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
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTLSClientConfig implements TLSClientConfig for testing
type mockTLSClientConfig struct {
	config *tls.Config
}

func (m *mockTLSClientConfig) GetClientConfig() *tls.Config {
	return m.config
}

func TestDialerWithCertificate(t *testing.T) {
	// Create test CA and certificates
	rootPool, serverCert := spiffetest.CreateWebCredentials(t)
	_, clientCert := spiffetest.CreateWebCredentials(t)

	// Start a TLS server
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		ClientAuth:   tls.NoClientCert,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Accept connections in goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Write something back to confirm connection works
		conn.Write([]byte("OK"))
	}()

	// Create dialer with client cert
	clientConfig := &tls.Config{
		Certificates:       []tls.Certificate{*clientCert},
		RootCAs:            rootPool,
		InsecureSkipVerify: true, // Skip verification for test simplicity
	}
	mockConfig := &mockTLSClientConfig{config: clientConfig}
	dialer := DialerWithCertificate(mockConfig, 5*time.Second, &net.Dialer{})

	// Test successful dial
	conn, err := dialer.DialContext(context.Background(), "tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Verify it's a TLS connection
	_, ok := conn.(*tls.Conn)
	assert.True(t, ok, "returned connection should be TLS")

	// Read response to confirm connection works
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "OK", string(buf[:n]))
}

func TestDialWithDialerRawConnFailure(t *testing.T) {
	// Test when raw connection fails (e.g., connection refused)
	config := &tls.Config{InsecureSkipVerify: true}

	_, err := dialWithDialer(&net.Dialer{}, context.Background(),
		100*time.Millisecond, "tcp", "127.0.0.1:1", config) // Port 1 should be closed
	assert.Error(t, err)
}

func TestDialWithDialerHandshakeFailure(t *testing.T) {
	// Start a plain TCP server (not TLS) to cause handshake failure
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	// Accept and immediately close to trigger handshake failure
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Close immediately to cause handshake failure
		conn.Close()
	}()

	config := &tls.Config{InsecureSkipVerify: true}

	_, err = dialWithDialer(&net.Dialer{}, context.Background(),
		1*time.Second, "tcp", listener.Addr().String(), config)
	assert.Error(t, err)
}

func TestDialWithDialerContextCancellation(t *testing.T) {
	// Start a TLS server that delays
	_, serverCert := spiffetest.CreateWebCredentials(t)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Accept but delay handshake
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Delay to allow context cancellation
		time.Sleep(2 * time.Second)
		conn.Close()
	}()

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	config := &tls.Config{InsecureSkipVerify: true}

	_, err = dialWithDialer(&net.Dialer{}, ctx,
		5*time.Second, "tcp", listener.Addr().String(), config)
	assert.Error(t, err)
}

func TestDialWithDialerTimeout(t *testing.T) {
	// Start a TLS server that delays handshake
	_, serverCert := spiffetest.CreateWebCredentials(t)
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	defer listener.Close()

	// Accept but don't complete handshake
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Hold connection open but delay to trigger timeout
		time.Sleep(5 * time.Second)
		conn.Close()
	}()

	config := &tls.Config{InsecureSkipVerify: true}

	// Use very short timeout
	_, err = dialWithDialer(&net.Dialer{}, context.Background(),
		50*time.Millisecond, "tcp", listener.Addr().String(), config)
	assert.Error(t, err)
}
