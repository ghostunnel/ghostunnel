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
	"encoding/pem"
	"io/ioutil"
	"os"
	"sync/atomic"
	"unsafe"

	"github.com/square/ghostunnel/internal/cipherhw"

	certigo "github.com/square/certigo/lib"
)

// certificate wraps a TLS certificate in a reloadable way
type certificate struct {
	keystorePath, keystorePass string
	cached                     unsafe.Pointer
}

// Build reloadable certificate
func buildCertificate(keystorePath, keystorePass string) (*certificate, error) {
	cert := &certificate{keystorePath, keystorePass, nil}
	err := cert.reload()
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Retrieve actual certificate
func (c *certificate) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return (*tls.Certificate)(atomic.LoadPointer(&c.cached)), nil
}

// Reload certificate
func (c *certificate) reload() error {
	keystore, err := os.Open(c.keystorePath)
	if err != nil {
		return err
	}

	var pemBlocks []*pem.Block
	err = certigo.ReadAsPEMFromFiles(
		[]*os.File{keystore},
		"",
		func(prompt string) string {
			return c.keystorePass
		},
		func(block *pem.Block) {
			pemBlocks = append(pemBlocks, block)
		})
	if err != nil {
		return err
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

func caBundle(caBundlePath string) (*x509.CertPool, error) {
	if caBundlePath == "" {
		return x509.SystemCertPool()
	}

	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	bundle := x509.NewCertPool()
	bundle.AppendCertsFromPEM(caBundleBytes)
	return bundle, nil
}

// buildConfig reads command-line options and builds a tls.Config
func buildConfig(caBundlePath string) (*tls.Config, error) {
	ca, err := caBundle(caBundlePath)
	if err != nil {
		return nil, err
	}

	// List of cipher suite preferences:
	// * We list ECDSA ahead of RSA to prefer ECDSA for multi-cert setups.
	// * We list AES-128 ahead of AES-256 for performance reasons.
	aesSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}

	chachaSuites := []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	// We prefer AES over ChaCha20 on platforms where Go has AES-NI support.
	var cipherSuites []uint16
	if cipherhw.AESGCMSupport() {
		cipherSuites = append(aesSuites, chachaSuites...)
	} else {
		cipherSuites = append(chachaSuites, aesSuites...)
	}

	return &tls.Config{
		// Certificates
		RootCAs:   ca,
		ClientCAs: ca,

		PreferServerCipherSuites: true,

		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
		CipherSuites: cipherSuites,
		CurvePreferences: []tls.CurveID{
			// P-256/X25519 have an ASM implementation, others do not (at least on x86-64).
			tls.X25519,
			tls.CurveP256,
		},
	}, nil
}
