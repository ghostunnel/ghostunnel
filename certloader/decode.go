/*-
 * Originally from github.com/square/certigo/lib
 *
 * Copyright 2025 Block, Inc.
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
 *
 * Modified for use in ghostunnel. Key changes:
 * - Removed display, linting, TLS info, and CT log functionality
 * - Rewrote PKCS#12 handling to use pkcs12.DecodeChain instead of deprecated ToPEM
 * - Added ED25519 key support for PKCS#12 and JCEKS keystores
 * - Added keyToPem support for ED25519 via PKCS#8 marshaling
 */

package certloader

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/smallstep/pkcs7"

	"github.com/ghostunnel/ghostunnel/certloader/jceks"
)

const (
	// maxReadSize is the maximum size of a file we'll read into memory (50MB).
	maxReadSize = 50 * 1024 * 1024
)

var fileExtToFormat = map[string]string{
	".pem":   "PEM",
	".crt":   "PEM",
	".p7b":   "PEM",
	".p7c":   "PEM",
	".p12":   "PKCS12",
	".pfx":   "PKCS12",
	".jceks": "JCEKS",
	".jks":   "JCEKS",
	".der":   "DER",
}

// formatForFile returns the file format (either from flags or based on file extension).
func formatForFile(file *bufio.Reader, filename, format string) (string, error) {
	if format != "" {
		return format, nil
	}

	guess, ok := fileExtToFormat[strings.ToLower(filepath.Ext(filename))]
	if ok {
		return guess, nil
	}

	data, err := file.Peek(4)
	if err != nil {
		return "", fmt.Errorf("unable to read file: %w", err)
	}

	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		return "PEM", nil
	}
	// Best-effort heuristic for DER vs PKCS12: both start with ASN.1 SEQUENCE
	// (0x30 0x82 ...). We check the third byte to guess, but this is fragile.
	// When auto-detection is ambiguous, prefer explicit --format flags.
	if magic&0xFFFF0000 == 0x30820000 {
		if magic&0x0000FF00 == 0x0300 {
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", ErrUnknownFormat
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func readCertsFromStream(reader io.Reader, format string, password string) ([]*pem.Block, error) {
	switch format {
	case "PEM":
		return readPEMBlocks(reader)
	case "DER":
		return readDERBlocks(reader)
	case "PKCS12":
		return readPKCS12Blocks(reader, password)
	case "JCEKS":
		return readJCEKSBlocks(reader, password)
	}
	return nil, fmt.Errorf("unknown file type '%s'", format)
}

func readPEMBlocks(reader io.Reader) ([]*pem.Block, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxReadSize))
	if err != nil {
		return nil, fmt.Errorf("error reading PEM data: %w", err)
	}

	var blocks []*pem.Block
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func readDERBlocks(reader io.Reader) ([]*pem.Block, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxReadSize))
	if err != nil {
		return nil, fmt.Errorf("unable to read input: %w", err)
	}

	x509Certs, err0 := x509.ParseCertificates(data)
	if err0 == nil {
		var blocks []*pem.Block
		for _, cert := range x509Certs {
			blocks = append(blocks, encodeX509ToPEM(cert))
		}
		return blocks, nil
	}

	p7, err1 := pkcs7.Parse(data)
	if err1 == nil {
		var blocks []*pem.Block
		for _, cert := range p7.Certificates {
			blocks = append(blocks, encodeX509ToPEM(cert))
		}
		return blocks, nil
	}

	return nil, fmt.Errorf("unable to parse DER data as X.509 (%v) or PKCS7 (%v)", err0, err1)
}

func readPKCS12Blocks(reader io.Reader, password string) ([]*pem.Block, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxReadSize))
	if err != nil {
		return nil, fmt.Errorf("unable to read input: %w", err)
	}

	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("unable to read keystore: %w", err)
	}

	var blocks []*pem.Block

	// Marshal the private key to PKCS#8 PEM. This supports RSA, ECDSA, and ED25519.
	keyBlock, err := keyToPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %w", err)
	}
	blocks = append(blocks, keyBlock)

	// Add the leaf certificate.
	blocks = append(blocks, encodeX509ToPEM(certificate))

	// Add CA certificates.
	for _, caCert := range caCerts {
		blocks = append(blocks, encodeX509ToPEM(caCert))
	}

	return blocks, nil
}

func readJCEKSBlocks(reader io.Reader, password string) ([]*pem.Block, error) {
	keyStore, err := jceks.LoadFromReader(io.LimitReader(reader, maxReadSize), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("unable to parse keystore: %w", err)
	}

	var blocks []*pem.Block

	for _, alias := range keyStore.ListCerts() {
		cert, err := keyStore.GetCert(alias)
		if err != nil {
			return nil, fmt.Errorf("unable to get certificate '%s': %w", alias, err)
		}
		blocks = append(blocks, encodeX509ToPEM(cert))
	}

	for _, alias := range keyStore.ListPrivateKeys() {
		key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("unable to recover private key '%s': %w", alias, err)
		}

		block, err := keyToPEM(key)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal private key: %w", err)
		}
		blocks = append(blocks, block)

		for _, cert := range certs {
			blocks = append(blocks, encodeX509ToPEM(cert))
		}
	}

	return blocks, nil
}

// encodeX509ToPEM converts an X.509 certificate into a PEM block.
func encodeX509ToPEM(cert *x509.Certificate) *pem.Block {
	return &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
}

// keyToPEM converts a private key into a PKCS#8 PEM block.
// Supports RSA, ECDSA, and ED25519 keys.
func keyToPEM(key crypto.PrivateKey) (*pem.Block, error) {
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("error marshaling private key: %w", err)
	}
	return &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: raw,
	}, nil
}
