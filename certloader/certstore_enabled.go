// +build certstore

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
	"fmt"
	"sync/atomic"
	"unsafe"

	"github.com/mastahyeti/certstore"
)

type certstoreCertificate struct {
	// Common name of keychain identity
	commonName string
	// Cached *tls.Certificate
	cached unsafe.Pointer
}

// SupportsKeychain returns true or false, depending on whether the
// binary was built with Certstore/Keychain support or not (requires CGO, recent
// Darwin to build).
func SupportsKeychain() bool {
	return true
}

// CertificateFromKeychainIdentity creates a reloadable certificate from a system keychain identity.
func CertificateFromKeychainIdentity(commonName string) (Certificate, error) {
	c := certstoreCertificate{
		commonName: commonName,
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *certstoreCertificate) Reload() error {
	store, err := certstore.Open()
	if err != nil {
		return err
	}

	identitites, err := store.Identities()
	if err != nil {
		return err
	}

	var certAndKey *tls.Certificate
	for _, identity := range identitites {
		chain, err := identity.CertificateChain()
		if err != nil {
			continue
		}

		signer, err := identity.Signer()
		if err != nil {
			continue
		}

		if chain[0].Subject.CommonName == c.commonName {
			certAndKey = &tls.Certificate{
				Certificate: serializeChain(chain),
				PrivateKey:  signer,
			}
			break
		}
	}

	if certAndKey != nil {
		atomic.StorePointer(&c.cached, unsafe.Pointer(certAndKey))
		return nil
	}

	return fmt.Errorf("unable to find identity with common name '%s' in keychain", c.commonName)
}

// GetCertificate retrieves the actual underlying tls.Certificate.
func (c *certstoreCertificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}

// GetClientCertificate retrieves the actual underlying tls.Certificate.
func (c *certstoreCertificate) GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}

func serializeChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
