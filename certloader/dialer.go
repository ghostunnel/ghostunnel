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
	"crypto/tls"
	"net"
	"time"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// Dialer is an interface for dialers. Can be a net.Dialer, http_dialer.HttpTunnel, or a dialer from this package.
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type mtlsDialer struct {
	config  TLSClientConfig
	timeout time.Duration
	dialer  Dialer
}

// DialerWithCertificate creates a dialer that reloads its certificate (if set) before dialing new connections.
// If the certificate is nil, the dialer will still work, but it won't supply client certificates on connections.
func DialerWithCertificate(config TLSClientConfig, timeout time.Duration, dialer Dialer) Dialer {
	return &mtlsDialer{
		config:  config,
		timeout: timeout,
		dialer:  dialer,
	}
}

func (d *mtlsDialer) Dial(network, address string) (net.Conn, error) {
	return dialWithDialer(d.dialer, d.timeout, network, address, d.config.GetClientConfig())
}

// Internal copy of tls.DialWithDialer, adapted so it can work with HTTP CONNECT dialers.
// See https://golang.org/pkg/crypto/tls/#DialWithDialer for original implementation.
func dialWithDialer(dialer Dialer, timeout time.Duration, network, addr string, config *tls.Config) (*tls.Conn, error) {
	errChannel := make(chan error, 2)
	time.AfterFunc(timeout, func() {
		errChannel <- timeoutError{}
	})

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)
	go func() {
		errChannel <- conn.Handshake()
	}()

	err = <-errChannel

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
}
