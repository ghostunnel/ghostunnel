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
	"fmt"
	"strings"

	"github.com/square/ghostunnel/certloader"
)

// Unsafe cipher suites available for compatibility reasons. To unlock these
// cipher suites you must use the (hidden) --allow-unsafe-cipher-suites flag.
// New cipher suites will be added here only if personally requested through a
// GitHub issue, and only to work around compatibility problems with large
// providers.
var unsafeCipherSuites = map[string][]uint16{
	// Needed for Azure PaaS compatibilty, see PR #235 on square/ghostunnel.
	"UNSAFE-AZURE": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	},
}

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
func buildCertificate(keystorePath, certPath, keyPath, keystorePass, caBundlePath string) (certloader.Certificate, error) {
	if hasPKCS11() {
		if keystorePath != "" {
			return buildCertificateFromPKCS11(keystorePath, caBundlePath)
		} else {
			return buildCertificateFromPKCS11(certPath, caBundlePath)
		}
	}
	if hasKeychainIdentity() {
		return certloader.CertificateFromKeychainIdentity(*keychainIdentity, caBundlePath)
	}
	if keyPath != "" && certPath != "" {
		return certloader.CertificateFromPEMFiles(certPath, keyPath, caBundlePath)
	}
	if keystorePath != "" {
		return certloader.CertificateFromKeystore(keystorePath, keystorePass, caBundlePath)
	}
	return certloader.NoCertificate(caBundlePath)
}

func buildCertificateFromPKCS11(certificatePath, caBundlePath string) (certloader.Certificate, error) {
	return certloader.CertificateFromPKCS11Module(certificatePath, caBundlePath, *pkcs11Module, *pkcs11TokenLabel, *pkcs11PIN)
}

func hasPKCS11() bool {
	return pkcs11Module != nil && *pkcs11Module != ""
}

func hasKeychainIdentity() bool {
	return keychainIdentity != nil && *keychainIdentity != ""
}

// buildConfig builds a generic tls.Config
func buildConfig(enabledCipherSuites string) (*tls.Config, error) {
	// List of cipher suite preferences:
	// * We list ECDSA ahead of RSA to prefer ECDSA for multi-cert setups.
	// * We list AES-128 ahead of AES-256 for performance reasons.

	suites := []uint16{}
	for _, suite := range strings.Split(enabledCipherSuites, ",") {
		name := strings.TrimSpace(suite)
		ciphers, ok := cipherSuites[name]
		if !ok && *allowUnsafeCipherSuites {
			ciphers, ok = unsafeCipherSuites[name]
		}
		if !ok {
			return nil, fmt.Errorf("invalid cipher suite '%s' selected", name)
		}

		suites = append(suites, ciphers...)
	}

	return &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             suites,
	}, nil
}

// buildClientConfig builds a tls.Config for clients
func buildClientConfig(enabledCipherSuites string) (*tls.Config, error) {
	// At the moment, we don't apply any extra settings on top of the generic
	// config for client contexts
	return buildConfig(enabledCipherSuites)
}

// buildServerConfig builds a tls.Config for servers
func buildServerConfig(enabledCipherSuites string) (*tls.Config, error) {
	config, err := buildConfig(enabledCipherSuites)
	if err != nil {
		return nil, err
	}

	// Require client cert by default
	config.ClientAuth = tls.RequireAndVerifyClientCert

	// P-256/X25519 have an ASM implementation, others do not (at least on x86-64).
	config.CurvePreferences = []tls.CurveID{
		tls.X25519,
		tls.CurveP256,
	}

	return config, nil
}
