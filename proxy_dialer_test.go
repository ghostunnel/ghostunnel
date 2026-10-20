/*-
 * Copyright 2026 Ghostunnel
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
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeProxy listens on localhost and runs handle for every accepted
// connection. It returns the proxy URL for the given scheme.
func fakeProxy(t *testing.T, scheme string, handle func(net.Conn)) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				handle(conn)
			}()
		}
	}()
	return &url.URL{Scheme: scheme, Host: ln.Addr().String()}
}

// silentProxy accepts connections but never answers.
func silentProxy(conn net.Conn) {
	_, _ = io.Copy(io.Discard, conn)
}

// echoConnectProxy answers a CONNECT request and then echoes the tunnel.
func echoConnectProxy(conn net.Conn) {
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	_, _ = io.Copy(conn, br)
}

// echoSOCKS5Proxy completes a no-auth SOCKS5 handshake for an IPv4 or
// domain name target and then echoes the tunnel.
func echoSOCKS5Proxy(conn net.Conn) {
	buf := make([]byte, 262)
	// Greeting: version, number of methods, methods.
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if _, err := io.ReadFull(conn, buf[:buf[1]]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}
	// Request: version, command, reserved, address type, address, port.
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	switch buf[3] {
	case 1:
		_, err := io.ReadFull(conn, buf[:4+2])
		if err != nil {
			return
		}
	case 3:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, buf[:int(buf[0])+2]); err != nil {
			return
		}
	default:
		return
	}
	if _, err := conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	_, _ = io.Copy(conn, conn)
}

func setConnectTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	orig := *connectTimeout
	*connectTimeout = d
	t.Cleanup(func() { *connectTimeout = orig })
}

func TestClientProxyDialerSilentProxyTimesOut(t *testing.T) {
	setConnectTimeout(t, 10*time.Second)

	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			dialer, _, err := clientProxyDialer(fakeProxy(t, scheme, silentProxy))
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()

			start := time.Now()
			conn, err := dialer.DialContext(ctx, "tcp", "target.example:443")
			if conn != nil {
				conn.Close()
			}
			assert.Error(t, err, "dial through a silent proxy must fail")
			assert.Less(t, time.Since(start), 5*time.Second, "dial must respect the context deadline")
		})
	}
}

func TestClientProxyDialerSilentProxyCancel(t *testing.T) {
	setConnectTimeout(t, 10*time.Second)

	dialer, _, err := clientProxyDialer(fakeProxy(t, "http", silentProxy))
	require.NoError(t, err)

	// No deadline: only cancellation can end the dial.
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", "target.example:443")
	if conn != nil {
		conn.Close()
	}
	assert.Error(t, err, "cancelled dial must fail")
	assert.Less(t, time.Since(start), 5*time.Second, "dial must stop when the context is cancelled")
}

// The deadline used while dialing must not carry over to the established
// tunnel, and cancelling the dial context afterwards must not break it.
func TestClientProxyDialerTunnelOutlivesDialContext(t *testing.T) {
	setConnectTimeout(t, 10*time.Second)

	proxies := map[string]func(net.Conn){
		"http":   echoConnectProxy,
		"socks5": echoSOCKS5Proxy,
	}
	for scheme, handle := range proxies {
		t.Run(scheme, func(t *testing.T) {
			dialer, _, err := clientProxyDialer(fakeProxy(t, scheme, handle))
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			conn, err := dialer.DialContext(ctx, "tcp", "target.example:443")
			require.NoError(t, err)
			defer conn.Close()
			cancel()

			// Wait until the dial deadline has passed.
			time.Sleep(400 * time.Millisecond)

			_, err = conn.Write([]byte("ping"))
			require.NoError(t, err)
			buf := make([]byte, 4)
			_, err = io.ReadFull(conn, buf)
			require.NoError(t, err)
			assert.Equal(t, "ping", string(buf))
		})
	}
}
