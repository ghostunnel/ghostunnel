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
	"encoding/pem"
	"sync/atomic"
	"unsafe"
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
}

type keystoreCertificate struct {
	// Keystore or PEM files path
	keystorePaths []string
	// Password for keystore (may be empty)
	keystorePassword string
	// File format as an indicator for certigo/lib
	format string
	// Cached *tls.Certificate
	cached unsafe.Pointer
}

// CertificateFromPEMFiles creates a reloadable certificate from a set of PEM files.
func CertificateFromPEMFiles(certificatePath, keyPath string) (Certificate, error) {
	c := keystoreCertificate{
		keystorePaths: []string{certificatePath, keyPath},
		format:        "PEM",
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// CertificateFromKeystore creates a reloadable certificate from a PKCS#12 keystore.
func CertificateFromKeystore(keystorePath, keystorePassword string) (Certificate, error) {
	c := keystoreCertificate{
		keystorePaths:    []string{keystorePath},
		keystorePassword: keystorePassword,
		format:           "",
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *keystoreCertificate) Reload() error {
	var pemBlocks []*pem.Block
	for _, path := range c.keystorePaths {
		blocks, err := readPEM(path, c.keystorePassword, c.format)
		if err != nil {
			return err
		}
		pemBlocks = append(pemBlocks, blocks...)
	}

	var pemBytes []byte
	for _, block := range pemBlocks {
		pemBytes = append(pemBytes, pem.EncodeToMemory(block)...)
	}

	certAndKey, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return err
	}

	certAndKey.Leaf, err = x509.ParseCertificate(certAndKey.Certificate[0])
	if err != nil {
		return err
	}

	atomic.StorePointer(&c.cached, unsafe.Pointer(&certAndKey))
	return nil
}

// GetCertificate retrieves the actual underlying tls.Certificate.
func (c *keystoreCertificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}

// GetClientCertificate retrieves the actual underlying tls.Certificate.
func (c *keystoreCertificate) GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}
