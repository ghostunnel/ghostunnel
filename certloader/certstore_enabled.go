//go:build cgo && (darwin || windows)

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
	"log"
	"sort"

	"github.com/ghostunnel/ghostunnel/certstore"
)

type certstoreCertificate struct {
	baseCertificate
	// Common name or serial number of keychain identity
	commonNameOrSerial string
	// Issuer name of keychain identity
	issuerName string
	// Root CA bundle path
	caBundlePath string
	// Require use of hardware token?
	requireToken bool
	// Added logger, useful for certstore logging
	logger *log.Logger
	// openStore allows injecting a custom store opener for testing.
	// If nil, defaults to certstore.Open.
	openStore func(*log.Logger) (certstore.Store, error)
}

// SupportsKeychain returns true or false, depending on whether the
// binary was built with Certstore/Keychain support or not (requires CGO,
// recent Darwin to build).
func SupportsKeychain() bool {
	return true
}

// CertificateFromKeychainIdentity creates a reloadable certificate from a system keychain identity.
func CertificateFromKeychainIdentity(
	commonNameOrSerial string, issuerName string, caBundlePath string, requireToken bool, logger *log.Logger,
) (Certificate, error) {
	c := certstoreCertificate{
		commonNameOrSerial: commonNameOrSerial,
		issuerName:         issuerName,
		caBundlePath:       caBundlePath,
		requireToken:       requireToken,
		logger:             logger,
	}
	err := c.Reload()
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Reload transparently reloads the certificate.
func (c *certstoreCertificate) Reload() error {
	opener := c.openStore
	if opener == nil {
		opener = certstore.Open
	}

	store, err := opener(c.logger)
	if err != nil {
		return err
	}

	flags := 0
	if c.requireToken {
		flags |= certstore.RequireToken
	}

	identities, err := store.Identities(flags)
	if err != nil {
		return err
	}

	// Filter any certificates with the matching serial/name/issuer,
	// as the keychain allows multiple certificates with the same name.
	var candidates []certstore.Identity
	for _, identity := range identities {
		chain, err := identity.CertificateChain()
		if err != nil {
			continue
		}

		hasIdentityFilter := c.commonNameOrSerial != ""
		hasIssuerFilter := c.issuerName != ""

		commonNameOrSerialMatches := hasIdentityFilter &&
			(chain[0].SerialNumber.String() == c.commonNameOrSerial ||
				chain[0].Subject.CommonName == c.commonNameOrSerial)

		issuerNameMatches := hasIssuerFilter &&
			chain[0].Issuer.CommonName == c.issuerName

		if hasIdentityFilter && hasIssuerFilter {
			// Both filters specified: require both to match, to support
			// e.g. two certs with the same name but from different issuers.
			if commonNameOrSerialMatches && issuerNameMatches {
				candidates = append(candidates, identity)
			}
		} else if hasIdentityFilter {
			if commonNameOrSerialMatches {
				candidates = append(candidates, identity)
			}
		} else if hasIssuerFilter {
			if issuerNameMatches {
				candidates = append(candidates, identity)
			}
		}
	}

	if len(candidates) == 0 {
		return fmt.Errorf("unable to find identity in keychain, check requested name/issuer")
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
		return fmt.Errorf("unable to read identity from keychain: %w", err)
	}
	signer, err := chosenIdentity.Signer()
	if err != nil {
		return fmt.Errorf("unable to read identity from keychain: %w", err)
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

	c.cachedCertificate.Store(certAndKey)
	c.cachedCertPool.Store(bundle)
	return nil
}

func serializeChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
