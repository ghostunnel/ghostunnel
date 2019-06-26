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
	"crypto/x509"
)

// Certificate wraps a TLS certificate and supports reloading at runtime.
type Certificate interface {
	// Reload will reload the certificate and private key. Subsequent calls
	// to GetCertificate/GetClientCertificate will return the newly loaded
	// certificate, if reloading was successful. If reloading failed, the old
	// state is kept.
	Reload() error

	// GetCertificate returns the current underlying certificate.
	// Can be used for tls.Config's GetCertificate callback.
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)

	// GetClientCertificate returns the current underlying certificate.
	// Can be used for tls.Config's GetClientCertificate callback.
	GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error)

	// GetTrustStore returns the most up-to-date version of the trust store / CA bundle.
	GetTrustStore() *x509.CertPool
}
