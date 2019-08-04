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
)

// TLSConfig is used to configure client or server TLS. It supports hot reloading.
type TLSConfigSource interface {
	// Reload will reload the TLS configuration. If reloading fails, the
	// existing configuration will be used. The client and server config
	// interface returned by GetClientConfig and GetServerConfig should reflect
	// any new configuration.
	Reload() error

	// CanServe returns true if the source can return configuration appropriate
	// for server roles (see GetServerConfig)
	CanServe() bool

	// GetClientConfig returns a TLSClientConfig interface that can be used to
	// obtain TLS client configuration. The base configuration is cloned and
	// used as a base for all returned TLS configuration.
	GetClientConfig(base *tls.Config) (TLSClientConfig, error)

	// GetServerConfig returns a TLSServerConfig interface that can be used to
	// obtain TLS server configuration. The base configuration is cloned and
	// used as a base for all returned TLS configuration. If the TLSConfig is
	// not appropriate for use as a server, false is returned.
	GetServerConfig(base *tls.Config) (TLSServerConfig, error)
}

type TLSClientConfig interface {
	// GetClientConfig returns a TLS configuration for use as a TLS client. It
	// is safe to call concurrently.
	GetClientConfig() *tls.Config
}

type TLSServerConfig interface {
	// GetServerConfig returns a TLS configuration for use as a TLS server. It
	// is safe to call concurrently.
	GetServerConfig() *tls.Config
}
