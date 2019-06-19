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
	"sync/atomic"
	"unsafe"
)

type trustBundle struct {
	// Root CA bundle path
	caBundlePath string
	// Cached *x509.CertPool
	cachedCertPool unsafe.Pointer
}

// NoCertificate creates an empty certificate with only a trust bundle.
func NoCertificate(caBundlePath string) (Certificate, error) {
	c := trustBundle{
		caBundlePath: caBundlePath,
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *trustBundle) Reload() error {
	bundle, err := LoadTrustStore(c.caBundlePath)
	if err != nil {
		return err
	}

	atomic.StorePointer(&c.cachedCertPool, unsafe.Pointer(bundle))
	return nil
}

// GetCertificate retrieves the actual underlying tls.Certificate.
func (c *trustBundle) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return nil, nil
}

// GetClientCertificate retrieves the actual underlying tls.Certificate.
func (c *trustBundle) GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return nil, nil
}

// GetTrustStore returns the most up-to-date version of the trust store / CA bundle.
func (c *trustBundle) GetTrustStore() *x509.CertPool {
	return (*x509.CertPool)(atomic.LoadPointer(&c.cachedCertPool))
}
