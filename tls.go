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
	"fmt"
	"io/ioutil"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

// parseKeystore takes a PKCS12 keystore and converts it into a series of
// serialized PEM blocks for certificates/private key. The keystore is expected
// to contain exactly one private key and one or more certificates.
func parseKeystore(data []byte, password string) (certs, key []byte, err error) {
	blocks, err := pkcs12.ToPEM(data, password)
	for _, block := range blocks {
		if strings.Contains(block.Type, "PRIVATE KEY") {
			if key != nil {
				return nil, nil, fmt.Errorf("invalid keystore: found multiple private keys in pkcs12 file")
			}
			key = pem.EncodeToMemory(block)
		} else if block.Type == "CERTIFICATE" {
			certs = append(certs, pem.EncodeToMemory(block)...)
			certs = append(certs, '\n')
		}
	}

	return
}

// buildConfig reads command-line options and builds a tls.Config
func buildConfig(keystorePath, keystorePass, caBundlePath string) (*tls.Config, error) {
	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(caBundleBytes)

	keystoreBytes, err := ioutil.ReadFile(keystorePath)
	if err != nil {
		return nil, err
	}

	certPEM, keyPEM, err := parseKeystore(keystoreBytes, keystorePass)
	if err != nil {
		return nil, fmt.Errorf("unable to parse keystore: %s", err)
	}

	certAndKey, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("unable to parse key pair: %s", err)
	}

	certAndKey.Leaf, err = x509.ParseCertificate(certAndKey.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("unable to parse leaf cert: %s", err)
	}

	return &tls.Config{
		// Certificates
		Certificates: []tls.Certificate{certAndKey},
		RootCAs:      caBundle,
		ClientCAs:    caBundle,

		// Options
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}, nil
}
