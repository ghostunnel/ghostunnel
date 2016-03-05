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

	"golang.org/x/crypto/pkcs12"
)

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

	pemBlocks, err := pkcs12.ToPEM(keystoreBytes, keystorePass)
	if err != nil {
		return nil, err
	}

	var pemBytes []byte
	for _, block := range pemBlocks {
		pemBytes = append(pemBytes, pem.EncodeToMemory(block)...)
	}

	certAndKey, err := tls.X509KeyPair(pemBytes, pemBytes)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		// Certificates
		Certificates: []tls.Certificate{certAndKey},
		RootCAs:      caBundle,
		ClientCAs:    caBundle,

		PreferServerCipherSuites: true,

		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
	}, nil
}
