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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"unsafe"

	"github.com/mastahyeti/certstore"
)

var (
	keychainIdentity = app.Flag("keychain-identity", "Use local keychain identity with given common name (instead of keystore file).").PlaceHolder("CN").String()
)

func validateKeystoreOrIdentity() error {
	if (*keystorePath == "") && (*keychainIdentity == "") {
		return fmt.Errorf("one of --keystore or --keychain-identity (or --disable-authentication in client mode) flags is required, try --help")
	}
	if (*keystorePath != "") && (*keychainIdentity != "") {
		return fmt.Errorf("--keystore and --keychain-identity flags are mutually exclusive")
	}
	return nil
}

func buildCertificateFromKeystoreOrIdentity() (*certificate, error) {
	if *keystorePath != "" {
		return buildCertificate(*keystorePath, *keystorePass)
	}

	if *keychainIdentity != "" {
		cert, err := loadIdentity(*keychainIdentity)
		if err != nil {
			return nil, fmt.Errorf("unable to load identity from keychain: %s", err)
		}

		return &certificate{false, "", "", unsafe.Pointer(&cert)}, nil
	}

	return &certificate{}, nil
}

func loadIdentity(commonName string) (tls.Certificate, error) {
	store, err := certstore.Open()
	if err != nil {
		return tls.Certificate{}, err
	}

	identitites, err := store.Identities()
	if err != nil {
		return tls.Certificate{}, err
	}

	for _, identity := range identitites {
		chain, err := identity.CertificateChain()
		if err != nil {
			continue
		}

		signer, err := identity.Signer()
		if err != nil {
			continue
		}

		if chain[0].Subject.CommonName == commonName {
			return tls.Certificate{
				Certificate: serializeChain(chain),
				PrivateKey:  signer,
			}, nil
		}
	}

	return tls.Certificate{}, fmt.Errorf("no identity with name '%s' found", commonName)
}

func serializeChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
