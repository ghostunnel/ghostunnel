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
	"sort"
	"sync/atomic"
	"unsafe"

	"github.com/mastahyeti/certstore"
)

type certstoreCertificate struct {
	// Common name of keychain identity
	commonName string
	// Root CA bundle path
	caBundlePath string
	// Cached *tls.Certificate
	cachedCertificate unsafe.Pointer
	// Cached *x509.CertPool
	cachedCertPool unsafe.Pointer
}

// SupportsKeychain returns true or false, depending on whether the
// binary was built with Certstore/Keychain support or not (requires CGO, recent
// Darwin to build).
func SupportsKeychain() bool {
	return true
}

// CertificateFromKeychainIdentity creates a reloadable certificate from a system keychain identity.
func CertificateFromKeychainIdentity(commonName string, caBundlePath string) (Certificate, error) {
	c := certstoreCertificate{
		commonName:   commonName,
		caBundlePath: caBundlePath,
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

	// filter any certificates with the matching name, as the keychain allows
	// multiple certificates with the same name
	var candidates []certstore.Identity
	for _, identity := range identitites {
		chain, err := identity.CertificateChain()
		if err != nil {
			continue
		}

		if chain[0].Subject.CommonName == c.commonName {
			candidates = append(candidates, identity)
		}
	}

	if len(candidates) == 0 {
		return fmt.Errorf("unable to find identity with common name '%s' in keychain", c.commonName)
	}

	// sort the candidates by descending NotAfter
	sort.Slice(candidates, func(i, j int) bool {
		leftChain, err := candidates[i].CertificateChain()
		if err != nil {
			return true
		}

		rightChain, err := candidates[j].CertificateChain()
		if err != nil {
			return false
		}

		return leftChain[0].NotAfter.After(rightChain[0].NotAfter)
	})

	// choose the certificate with the NotAfter furthest in the future, which is
	// the first item after the sort
	chosenIdentity := candidates[0]
	chain, err := chosenIdentity.CertificateChain()
	if err != nil {
		return fmt.Errorf("unable to find identity with common name '%s' in keychain", c.commonName)
	}
	signer, err := chosenIdentity.Signer()
	if err != nil {
		return fmt.Errorf("unable to find identity with common name '%s' in keychain", c.commonName)
	}

	certAndKey := &tls.Certificate{
		Leaf:        chain[0],
		Certificate: serializeChain(chain),
		PrivateKey:  signer,
	}

	bundle, err := LoadTrustStore(c.caBundlePath)
	if err != nil {
		return err
	}

	atomic.StorePointer(&c.cachedCertificate, unsafe.Pointer(certAndKey))
	atomic.StorePointer(&c.cachedCertPool, unsafe.Pointer(bundle))
	return nil
}

// GetCertificate retrieves the actual underlying tls.Certificate.
func (c *certstoreCertificate) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cachedCertificate)), nil
}

// GetClientCertificate retrieves the actual underlying tls.Certificate.
func (c *certstoreCertificate) GetClientCertificate(certInfo *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cachedCertificate)), nil
}

// GetTrustStore returns the most up-to-date version of the trust store / CA bundle.
func (c *certstoreCertificate) GetTrustStore() *x509.CertPool {
	return (*x509.CertPool)(atomic.LoadPointer(&c.cachedCertPool))
}

func serializeChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
