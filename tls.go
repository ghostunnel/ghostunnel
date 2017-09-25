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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	certigo "github.com/square/certigo/lib"
)

var cipherSuites = map[string][]uint16{
	"AES": []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	},
	"CHACHA": []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	},
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "tls: DialWithDialer timed out" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

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
	var err error
	if hasPKCS11() {
		err = c.reloadFromPKCS11()
	} else {
		err = c.reloadFromPEM()
	}

	if err == nil {
		cert, _ := c.getCertificate(nil)
		logger.Printf("loaded certificate with common name '%s'", cert.Leaf.Subject.CommonName)
	}
	return err
}

func (c *certificate) reloadFromPEM() error {
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

func (c *certificate) reloadFromPKCS11() error {
	// Expecting keystore file to only have certificate,
	// with the private key being in an HSM/PKCS11 module.
	keystore, err := os.Open(c.keystorePath)
	if err != nil {
		return err
	}

	certAndKey := tls.Certificate{}
	err = certigo.ReadAsX509FromFiles(
		[]*os.File{keystore}, "", nil,
		func(cert *x509.Certificate, err error) {
			if err != nil {
				logger.Printf("error during keystore read: %s", err)
				return
			}
			if certAndKey.Leaf == nil {
				certAndKey.Leaf = cert
			}
			certAndKey.Certificate = append(certAndKey.Certificate, cert.Raw)
		})
	if err != nil {
		return err
	}

	// Reuse previously loaded PKCS11 private key if we already have it. We want to
	// avoid reloading the key every time the cert reloads, as it's a potentially
	// expensive operation that calls out into a shared library.
	if c.cached != nil {
		old, _ := c.getCertificate(nil)
		certAndKey.PrivateKey = old.PrivateKey
	} else {
		privateKey, err := newPKCS11(certAndKey.Leaf.PublicKey)
		if err != nil {
			return err
		}
		certAndKey.PrivateKey = privateKey
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
	ok := bundle.AppendCertsFromPEM(caBundleBytes)
	if !ok {
		return nil, errors.New("unable to read certificates from CA bundle")
	}

	return bundle, nil
}

// Internal copy of tls.DialWithDialer, adapter so it can work with HTTP CONNECT dialers.
// See: https://golang.org/pkg/crypto/tls/#DialWithDialer
func dialWithDialer(dialer Dialer, timeout time.Duration, network, addr string, config *tls.Config) (*tls.Conn, error) {
	var errChannel chan error
	if timeout != 0 {
		errChannel = make(chan error, 2)
		time.AfterFunc(timeout, func() {
			errChannel <- timeoutError{}
		})
	}

	rawConn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, config)
	if timeout == 0 {
		err = conn.Handshake()
	} else {
		go func() {
			errChannel <- conn.Handshake()
		}()

		err = <-errChannel
	}

	if err != nil {
		rawConn.Close()
		return nil, err
	}

	return conn, nil
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

	suites := []uint16{}
	for _, suite := range strings.Split(*enabledCipherSuites, ",") {
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
