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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	netproxy "golang.org/x/net/proxy"
)

// aLongTimeAgo is a deadline in the past, used to unblock pending I/O.
var aLongTimeAgo = time.Unix(1, 0)

// connectDialer opens tunnels through an HTTP CONNECT proxy. The connection
// to the proxy is made by forward, which wraps it in TLS for https:// proxies.
// The dial context bounds the whole exchange with the proxy, so a proxy that
// accepts the connection but never answers cannot hang the dial.
type connectDialer struct {
	proxyAddr string
	auth      string // Proxy-Authorization value, empty if none
	forward   netproxy.ContextDialer
}

// newConnectDialer returns a dialer for the http:// or https:// proxy URL u.
// Without an explicit port, the proxy is reached on 80 for http and 443 for
// https. Credentials in the URL are sent as basic proxy authentication.
func newConnectDialer(u *url.URL, forward netproxy.ContextDialer) *connectDialer {
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	d := &connectDialer{
		proxyAddr: net.JoinHostPort(u.Hostname(), port),
		forward:   forward,
	}
	if u.User != nil {
		password, _ := u.User.Password()
		credentials := u.User.Username() + ":" + password
		d.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(credentials))
	}
	return d
}

func (d *connectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("unsupported network %q for HTTP CONNECT proxy", network)
	}
	conn, err := d.forward.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("unable to dial proxy %q: %w", d.proxyAddr, err)
	}
	tunnel, err := d.connect(ctx, conn, address)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return tunnel, nil
}

// connect asks the proxy on conn for a tunnel to address. The context
// deadline applies to the CONNECT exchange only and is removed once the
// tunnel is up.
func (d *connectDialer) connect(ctx context.Context, conn net.Conn, address string) (net.Conn, error) {
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(aLongTimeAgo)
	})

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}
	if d.auth != "" {
		req.Header.Set("Proxy-Authorization", d.auth)
	}

	br := bufio.NewReader(conn)
	var resp *http.Response
	err := req.Write(conn)
	if err == nil {
		resp, err = http.ReadResponse(br, req)
	}
	if !stop() && err == nil {
		// The context ended just as the exchange finished. Its deadline is
		// now in the past, so the connection is unusable.
		err = ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to complete CONNECT to %q via proxy: %w", address, err)
	}
	// After a 2xx response the connection is the tunnel, so there is no body
	// to read; closing it does not consume tunnel data.
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("proxy refused CONNECT to %q: %s", address, resp.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	if br.Buffered() > 0 {
		// The proxy sent tunnel data right behind its response; keep it.
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn is a net.Conn whose first reads are served from r, which holds
// data read past the end of the proxy's CONNECT response.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}
