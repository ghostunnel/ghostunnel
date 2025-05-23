/*-
 * Copyright 2018 Square Inc.
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
	"time"

	netproxy "golang.org/x/net/proxy"
)

type mtlsDialer struct {
	config  TLSClientConfig
	timeout time.Duration
	dialer  netproxy.ContextDialer
}

// DialerWithCertificate creates a dialer that reloads its certificate (if set) before dialing new connections.
// If the certificate is nil, the dialer will still work, but it won't supply client certificates on connections.
func DialerWithCertificate(config TLSClientConfig, timeout time.Duration, dialer netproxy.ContextDialer) netproxy.ContextDialer {
	return &mtlsDialer{
		config:  config,
		timeout: timeout,
		dialer:  dialer,
	}
}

func (d *mtlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialWithDialer(d.dialer, ctx, d.timeout, network, address, d.config.GetClientConfig())
}

// Internal copy of tls.DialWithDialer, adapted so it can work with proxy dialers.
// See https://golang.org/pkg/crypto/tls/#DialWithDialer for original implementation.
func dialWithDialer(dialer netproxy.ContextDialer, ctx context.Context, timeout time.Duration, network, addr string, config *tls.Config) (*tls.Conn, error) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()

	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	return conn, nil
}
