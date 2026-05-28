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
	"crypto/x509"
	"net"
	"time"

	netproxy "golang.org/x/net/proxy"
)

// VerifyBuilder returns a VerifyPeerCertificate callback bound to a
// specific context. The dialer invokes it once per connection so callers
// can plumb the per-dial context into TLS verification (e.g. for OPA
// policy evaluation that should be cancelled with the dial).
type VerifyBuilder func(ctx context.Context) VerifyPeerCertificateFunc

type mtlsDialer struct {
	config        TLSClientConfig
	verifyBuilder VerifyBuilder
	timeout       time.Duration
	dialer        netproxy.ContextDialer
}

// DialerWithCertificate creates a dialer that reloads its certificate (if set) before dialing new connections.
// If the certificate is nil, the dialer will still work, but it won't supply client certificates on connections.
//
// If verify is non-nil, it is invoked per-dial to produce a VerifyPeerCertificate
// callback that has access to the per-dial context. The callback composes with
// any existing VerifyPeerCertificate on the *tls.Config returned by the config
// source (for example, the SPIFFE wrapper), running the existing callback first.
func DialerWithCertificate(config TLSClientConfig, verify VerifyBuilder, timeout time.Duration, dialer netproxy.ContextDialer) netproxy.ContextDialer {
	return &mtlsDialer{
		config:        config,
		verifyBuilder: verify,
		timeout:       timeout,
		dialer:        dialer,
	}
}

func (d *mtlsDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	cfg := d.config.GetClientConfig()
	if d.verifyBuilder != nil {
		ours := d.verifyBuilder(ctx)
		if existing := cfg.VerifyPeerCertificate; existing != nil {
			cfg.VerifyPeerCertificate = func(raw [][]byte, chains [][]*x509.Certificate) error {
				if err := existing(raw, chains); err != nil {
					return err
				}
				return ours(raw, chains)
			}
		} else {
			cfg.VerifyPeerCertificate = ours
		}
	}
	return dialWithDialer(d.dialer, ctx, d.timeout, network, address, cfg)
}

// Internal copy of tls.DialWithDialer, adapted so it can work with proxy dialers.
// See https://pkg.go.dev/crypto/tls#DialWithDialer for original implementation.
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
