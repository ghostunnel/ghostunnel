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
	"encoding/base64"
	"errors"
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

// addrRecordingDialer records the address it was asked to dial and fails,
// so tests can see where a dialer would connect without a network.
type addrRecordingDialer struct {
	addr string
}

func (d *addrRecordingDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error) {
	d.addr = addr
	return nil, errors.New("not dialing")
}

func TestConnectDialerDefaultPort(t *testing.T) {
	for _, tc := range []struct {
		proxyURL string
		expected string
	}{
		{"http://proxy.example.com", "proxy.example.com:80"},
		{"https://proxy.example.com", "proxy.example.com:443"},
		{"http://proxy.example.com:3128", "proxy.example.com:3128"},
		{"http://[::1]", "[::1]:80"},
	} {
		t.Run(tc.proxyURL, func(t *testing.T) {
			u, err := url.Parse(tc.proxyURL)
			require.NoError(t, err)

			fwd := &addrRecordingDialer{}
			_, err = newConnectDialer(u, fwd).DialContext(context.Background(), "tcp", "target.example:443")
			require.Error(t, err)
			assert.Equal(t, tc.expected, fwd.addr)
		})
	}
}

func TestConnectDialerRejectsNonTCP(t *testing.T) {
	fwd := &addrRecordingDialer{}
	_, err := newConnectDialer(&url.URL{Scheme: "http", Host: "proxy.example.com"}, fwd).
		DialContext(context.Background(), "udp", "target.example:443")
	require.Error(t, err)
	assert.Empty(t, fwd.addr, "must not dial the proxy for a non-TCP network")
}

func TestConnectDialerProxyAuthorization(t *testing.T) {
	headers := make(chan http.Header, 1)
	proxyURL := fakeProxy(t, "http", func(conn net.Conn) {
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		headers <- req.Header
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\n")
	})
	proxyURL.User = url.UserPassword("alice", "s3cret")

	conn, err := newConnectDialer(proxyURL, &net.Dialer{}).DialContext(context.Background(), "tcp", "target.example:443")
	require.NoError(t, err)
	conn.Close()

	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
	assert.Equal(t, want, (<-headers).Get("Proxy-Authorization"))
}

func TestConnectDialerRefused(t *testing.T) {
	proxyURL := fakeProxy(t, "http", func(conn net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
	})

	_, err := newConnectDialer(proxyURL, &net.Dialer{}).DialContext(context.Background(), "tcp", "target.example:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403 Forbidden")
}

// Data the proxy sends in the same write as its CONNECT response belongs to
// the tunnel and must not be lost.
func TestConnectDialerKeepsDataAfterResponse(t *testing.T) {
	proxyURL := fakeProxy(t, "http", func(conn net.Conn) {
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\n\r\nearly")
	})

	conn, err := newConnectDialer(proxyURL, &net.Dialer{}).DialContext(context.Background(), "tcp", "target.example:443")
	require.NoError(t, err)
	defer conn.Close()

	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "early", string(buf))
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
