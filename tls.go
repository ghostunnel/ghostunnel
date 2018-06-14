/*-
 * Copyright 2015 Square Inc.
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
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/square/ghostunnel/certloader"
)

var cipherSuites = map[string][]uint16{
	"AES": {
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	"CHACHA": {
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	},
}

// Build reloadable certificate
func buildCertificate(keystorePath, keystorePass string) (certloader.Certificate, error) {
	if hasPKCS11() {
		return buildCertificateFromPKCS11(keystorePath)
	}
	if hasKeychainIdentity() {
		return buildCertificateFromCertstore()
	}
	if keystorePath != "" {
		return certloader.CertificateFromKeystore(keystorePath, keystorePass)
	}
	return nil, nil
}

func buildCertificateFromPKCS11(certificatePath string) (certloader.Certificate, error) {
	return certloader.CertificateFromPKCS11Module(certificatePath, *pkcs11Module, *pkcs11TokenLabel, *pkcs11PIN)
}

func hasPKCS11() bool {
	return pkcs11Module != nil && *pkcs11Module != ""
}

func buildCertificateFromCertstore() (certloader.Certificate, error) {
	return certloader.CertificateFromKeychainIdentity(*keychainIdentity)
}

func hasKeychainIdentity() bool {
	return keychainIdentity != nil && *keychainIdentity != ""
}

func caBundle(caBundlePath string) (*x509.CertPool, error) {
	if caBundlePath == "" {
		return x509.SystemCertPool()
	}

	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	bundle := x509.NewCertPool()
	ok := bundle.AppendCertsFromPEM(caBundleBytes)
	if !ok {
		return nil, errors.New("unable to read certificates from CA bundle")
	}

	return bundle, nil
}

// buildConfig reads command-line options and builds a tls.Config
func buildConfig(enabledCipherSuites string, caBundlePath string) (*tls.Config, error) {
	ca, err := caBundle(caBundlePath)
	if err != nil {
		return nil, err
	}

	// List of cipher suite preferences:
	// * We list ECDSA ahead of RSA to prefer ECDSA for multi-cert setups.
	// * We list AES-128 ahead of AES-256 for performance reasons.

	suites := []uint16{}
	for _, suite := range strings.Split(enabledCipherSuites, ",") {
		ciphers, ok := cipherSuites[strings.TrimSpace(suite)]
		if !ok {
			return nil, fmt.Errorf("invalid cipher suite '%s' selected", suite)
		}

		suites = append(suites, ciphers...)
	}

	return &tls.Config{
		// Certificates
		RootCAs:   ca,
		ClientCAs: ca,

		PreferServerCipherSuites: true,

		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: suites,
		CurvePreferences: []tls.CurveID{
			// P-256/X25519 have an ASM implementation, others do not (at least on x86-64).
			tls.X25519,
			tls.CurveP256,
		},
	}, nil
}
