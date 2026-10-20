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
	"context"
	"net"
	"time"

	"github.com/ghostunnel/ghostunnel/certloader"
	netproxy "golang.org/x/net/proxy"
)

// The HTTP CONNECT dialer (go.connect-proxy-scheme) ignores the context while
// it writes the CONNECT request and reads the response, so a proxy that
// accepts the connection but never answers would hang the dial forever,
// regardless of --connect-timeout. The two wrappers below bound that exchange
// for every proxy scheme:
//
//   - boundedForwardDialer dials the proxy itself. It puts the context
//     deadline on the proxy connection and arranges for blocked I/O on it to
//     fail if the context is cancelled.
//   - boundedProxyDialer wraps the whole proxy dialer. Once the tunnel is up
//     it removes the deadline again, so it does not apply to the established
//     connection.
//
// The two find each other through a value on the dial context, which is
// passed from the proxy dialer down to the forward dialer.

// aLongTimeAgo is a deadline in the past, used to unblock pending I/O.
var aLongTimeAgo = time.Unix(1, 0)

type proxyConnKey struct{}

// proxyConn records the connection to the proxy made during one dial.
type proxyConn struct {
	conn net.Conn
	stop func() bool
}

type boundedForwardDialer struct {
	certloader.ContextDialer
}

func (d boundedForwardDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d boundedForwardDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.ContextDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	pc, ok := ctx.Value(proxyConnKey{}).(*proxyConn)
	if !ok || pc.conn != nil {
		return conn, nil
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, err
		}
	}
	pc.conn = conn
	pc.stop = context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(aLongTimeAgo)
	})
	return conn, nil
}

type boundedProxyDialer struct {
	netproxy.ContextDialer
}

func (d boundedProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	pc := &proxyConn{}
	conn, err := d.ContextDialer.DialContext(context.WithValue(ctx, proxyConnKey{}, pc), network, address)
	if pc.stop != nil && !pc.stop() {
		// The context was cancelled while dialing: the deadline is now in
		// the past, so the connection is unusable even if the dial returned.
		if conn != nil {
			conn.Close()
		}
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	if pc.conn != nil {
		if err := pc.conn.SetDeadline(time.Time{}); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}
