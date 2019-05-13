// +build cgo,!nopkcs11

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
	"sync/atomic"
	"unsafe"

	"github.com/letsencrypt/pkcs11key"
)

type pkcs11Certificate struct {
	// Certificate chain corresponding to key
	certificatePath string
	// Params for loading key from a PKCS#11 module
	modulePath, tokenLabel, pin string
	// Cached *tls.Certificate
	cached unsafe.Pointer
}

// SupportsPKCS11 returns true or false, depending on whether the binary
// was built with PKCS11 support or not (requires CGO to build).
func SupportsPKCS11() bool {
	return true
}

// CertificateFromPKCS11Module creates a reloadable certificate from a PKCS#11 module.
func CertificateFromPKCS11Module(certificatePath, modulePath, tokenLabel, pin string) (Certificate, error) {
	c := pkcs11Certificate{
		certificatePath: certificatePath,
		modulePath:      modulePath,
		tokenLabel:      tokenLabel,
		pin:             pin,
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *pkcs11Certificate) Reload() error {
	// Expecting certificate file to only have certificate chain,
	// with the (fixed) private key being in an HSM/PKCS11 module.
	certs, err := readX509(c.certificatePath)
	if err != nil {
		return err
	}

	certAndKey := tls.Certificate{
		Leaf: certs[0],
	}
	for _, cert := range certs {
		certAndKey.Certificate = append(certAndKey.Certificate, cert.Raw)
	}

	// Reuse previously loaded PKCS11 private key if we already have it.
	// We want to avoid reloading the key every time the cert reloads, as it's
	// a potentially expensive operation that calls out into a shared library.
	if c.cached != nil {
		old, _ := c.GetCertificate(nil)
		certAndKey.PrivateKey = old.PrivateKey
	} else {
		privateKey, err := pkcs11key.New(c.modulePath, c.tokenLabel, c.pin, certAndKey.Leaf.PublicKey)
		if err != nil {
			return err
		}
		certAndKey.PrivateKey = privateKey
	}

	atomic.StorePointer(&c.cached, unsafe.Pointer(&certAndKey))
	return nil
}

// GetCertificate retrieves the actual underlying tls.Certificate.
func (c *pkcs11Certificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}

// GetClientCertificate retrieves the actual underlying tls.Certificate.
func (c *pkcs11Certificate) GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}
