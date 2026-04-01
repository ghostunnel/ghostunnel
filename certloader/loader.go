/*-
 * Copyright 2018 Square Inc.
 * SPDX-License-Identifier: Apache-2.0
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
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func readCertificateFile(path, password, format string) ([]*pem.Block, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := bufio.NewReaderSize(file, 4)
	format, err = formatForFile(reader, file.Name(), format)
	if err != nil {
		return nil, fmt.Errorf("failed to detect format for '%s': %w", path, err)
	}

	pemBlocks, err := readCertsFromStream(reader, format, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse '%s': %w", path, err)
	}
	if len(pemBlocks) == 0 {
		return nil, fmt.Errorf("error reading file '%s', no certificates found", path)
	}

	return pemBlocks, nil
}

// readX509 reads X.509 certificates from a PEM file. Unlike the original certigo
// implementation, this fails fast on the first unparseable certificate block rather
// than accumulating errors and continuing.
func readX509(path string) ([]*x509.Certificate, error) {
	pemBlocks, err := readCertificateFile(path, "", "PEM")
	if err != nil {
		return nil, err
	}

	var out []*x509.Certificate
	for _, block := range pemBlocks {
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("error reading file '%s': %w", path, err)
		}
		out = append(out, cert)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates found in file '%s'", path)
	}
	return out, nil
}

// LoadTrustStore loads a CA bundle from the given path, or returns the system cert pool if empty.
func LoadTrustStore(caBundlePath string) (*x509.CertPool, error) {
	if caBundlePath == "" {
		return x509.SystemCertPool()
	}

	caBundleBytes, err := os.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	bundle := x509.NewCertPool()
	ok := bundle.AppendCertsFromPEM(caBundleBytes)
	if !ok {
		return nil, ErrNoCACerts
	}

	return bundle, nil
}
