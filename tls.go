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
	"log"
	"strings"

	"github.com/ghostunnel/ghostunnel/certloader"
)

// Unsafe cipher suites available for compatibility reasons. To unlock these
// cipher suites you must use the (hidden) --allow-unsafe-cipher-suites flag.
// New cipher suites will be added here only if personally requested through a
// GitHub issue, and only to work around compatibility problems with large
// providers.
var unsafeCipherSuites = map[string][]uint16{
	// Needed for 'Azure Cache for Redis', see PR #239 on square/ghostunnel.
	"UNSAFE-AZURE": {
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	},
}

var cipherSuites = map[string][]uint16{
	"AES": {
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	"CHACHA": {
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	},
}

// Build reloadable certificate
func buildCertificate(keystorePath, certPath, keyPath, keystorePass, caBundlePath string, logger *log.Logger) (certloader.Certificate, error) {
	if hasPKCS11() {
		logger.Printf("using PKCS#11 module as certificate source")
		if keystorePath != "" {
			return buildCertificateFromPKCS11(keystorePath, caBundlePath, logger)
		} else {
			return buildCertificateFromPKCS11(certPath, caBundlePath, logger)
		}
	}
	if hasKeychainIdentity() {
		logger.Printf("using operating system keychain as certificate source")
		return certloader.CertificateFromKeychainIdentity(*keychainIdentity, *keychainIssuer, caBundlePath, *keychainRequireToken, logger)
	}
	if keyPath != "" && certPath != "" {
		logger.Printf("using cert/key files on disk as certificate source")
		return certloader.CertificateFromPEMFiles(certPath, keyPath, caBundlePath)
	}
	if keystorePath != "" {
		logger.Printf("using keystore file on disk as certificate source")
		return certloader.CertificateFromKeystore(keystorePath, keystorePass, caBundlePath)
	}
	logger.Printf("no cert source configured -- running without certificate")
	return certloader.NoCertificate(caBundlePath)
}

func buildCertificateFromPKCS11(certificatePath, caBundlePath string, logger *log.Logger) (certloader.Certificate, error) {
	return certloader.CertificateFromPKCS11Module(certificatePath, caBundlePath, *pkcs11Module, *pkcs11TokenLabel, *pkcs11PIN, logger)
}

func hasPKCS11() bool {
	return pkcs11Module != nil && *pkcs11Module != ""
}

func hasKeychainIdentity() bool {
	return (keychainIdentity != nil && *keychainIdentity != "") || (keychainIssuer != nil && *keychainIssuer != "")
}

// parseTLSVersion converts a TLS version string to the corresponding crypto/tls constant
func parseTLSVersion(version string) (uint16, error) {
	switch strings.ToUpper(version) {
	case "TLS1.2":
		return tls.VersionTLS12, nil
	case "TLS1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS version: %s", version)
	}
}

// buildConfig builds a generic tls.Config
func buildConfig(enabledCipherSuites string, maxTLSVersion string) (*tls.Config, error) {
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

	config := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		CipherSuites: suites,
	}

	if maxTLSVersion != "" {
		maxVer, err := parseTLSVersion(maxTLSVersion)
		if err != nil {
			return nil, fmt.Errorf("invalid max TLS version: %v", err)
		}
		config.MaxVersion = maxVer
	}

	return config, nil
}

// buildClientConfig builds a tls.Config for clients
func buildClientConfig(enabledCipherSuites string, maxTLSVersion string) (*tls.Config, error) {
	// At the moment, we don't apply any extra settings on top of the generic
	// config for client contexts
	return buildConfig(enabledCipherSuites, maxTLSVersion)
}

// buildServerConfig builds a tls.Config for servers
func buildServerConfig(enabledCipherSuites string, maxTLSVersion string) (*tls.Config, error) {
	config, err := buildConfig(enabledCipherSuites, maxTLSVersion)
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
