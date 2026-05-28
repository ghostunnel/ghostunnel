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

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

// VerifyPeerCertificateFunc matches the signature of tls.Config.VerifyPeerCertificate.
type VerifyPeerCertificateFunc func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error

// Listener holds a *net.Listener, wrapping incoming connections in TLS,
// overriding Accept() to make sure we reload the trust bundle on new incoming
// connections. This allows for reloading the CA bundle at runtime without
// restarting the listener.
type Listener struct {
	net.Listener

	config TLSServerConfig
	verify VerifyPeerCertificateFunc
}

// NewListener creates a new TLS listener that wraps the given net.Listener.
func NewListener(listener net.Listener, config TLSServerConfig) *Listener {
	return &Listener{
		Listener: listener,
		config:   config,
	}
}

// SetVerify installs a VerifyPeerCertificate callback that is applied to the
// per-connection cloned *tls.Config before each handshake. It must be called
// before Accept is first invoked. If the underlying config source already
// supplies a VerifyPeerCertificate (for example, the SPIFFE wrapper), the
// listener composes the supplied callback after the existing one so both run.
func (l *Listener) SetVerify(verify VerifyPeerCertificateFunc) {
	l.verify = verify
}

// Accept waits for and returns the next TLS-wrapped connection to the listener.
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cfg := l.config.GetServerConfig()
	if l.verify != nil {
		ours := l.verify
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
	return tls.Server(c, cfg), nil
}
