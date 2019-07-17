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
	"net"
)

// Listener holds a *net.Listener, wrapping incoming connections in TLS,
// overriding Accept() to make sure we reload the trust bundle on new incoming
// connections. This allows for reloading the CA bundle at runtime without
// restarting the listener.
type Listener struct {
	net.Listener

	cert   Certificate
	config TLSServerConfig
}

func NewListener(listener net.Listener, config TLSServerConfig) *Listener {
	return &Listener{
		Listener: listener,
		config:   config,
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return tls.Server(c, l.config.GetServerConfig()), nil
}
