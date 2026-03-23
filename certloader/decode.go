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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/ghostunnel/ghostunnel/certloader/jceks"
	"github.com/ghostunnel/ghostunnel/certloader/pkcs7"
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
		return "", fmt.Errorf("unable to read file: %s", err)
	}

	magic := binary.BigEndian.Uint32(data)
	if magic == 0xCECECECE || magic == 0xFEEDFEED {
		return "JCEKS", nil
	}
	if magic == 0x2D2D2D2D || magic == 0x434f4e4e {
		return "PEM", nil
	}
	if magic&0xFFFF0000 == 0x30820000 {
		if magic&0x0000FF00 == 0x0300 {
			return "DER", nil
		}
		return "PKCS12", nil
	}

	return "", fmt.Errorf("unable to guess file format")
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func readCertsFromStream(reader io.Reader, format string, password string) ([]*pem.Block, error) {
	format = strings.TrimSpace(format)
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
	scanner := pemScanner(reader)
	var blocks []*pem.Block
	for scanner.Scan() {
		block, _ := pem.Decode(scanner.Bytes())
		blocks = append(blocks, block)
	}
	return blocks, nil
}

func readDERBlocks(reader io.Reader) ([]*pem.Block, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read input: %s", err)
	}

	x509Certs, err0 := x509.ParseCertificates(data)
	if err0 == nil {
		var blocks []*pem.Block
		for _, cert := range x509Certs {
			blocks = append(blocks, encodeX509ToPEM(cert))
		}
		return blocks, nil
	}

	p7bBlocks, err1 := pkcs7.ParseSignedData(data)
	if err1 == nil {
		var blocks []*pem.Block
		for _, block := range p7bBlocks {
			blocks = append(blocks, &pem.Block{
				Type:  "PKCS7",
				Bytes: block.Raw,
			})
		}
		return blocks, nil
	}

	return nil, fmt.Errorf("unable to parse certificates from DER data\n* X.509 parser gave: %s\n* PKCS7 parser gave: %s", err0, err1)
}

func readPKCS12Blocks(reader io.Reader, password string) ([]*pem.Block, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to read input: %s", err)
	}

	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("unable to read keystore: %s", err)
	}

	var blocks []*pem.Block

	// Marshal the private key to PKCS#8 PEM. This supports RSA, ECDSA, and ED25519.
	keyBlock, err := keyToPem(privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal private key: %s", err)
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
	keyStore, err := jceks.LoadFromReader(reader, []byte(password))
	if err != nil {
		return nil, fmt.Errorf("unable to parse keystore: %s", err)
	}

	var blocks []*pem.Block

	for _, alias := range keyStore.ListCerts() {
		cert, _ := keyStore.GetCert(alias)
		blocks = append(blocks, encodeX509ToPEM(cert))
	}

	for _, alias := range keyStore.ListPrivateKeys() {
		key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("unable to parse keystore: %s", err)
		}

		block, err := keyToPem(key)
		if err != nil {
			return nil, fmt.Errorf("problem reading key: %s", err)
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

// keyToPem converts a private key into a PEM block.
// Supports RSA, ECDSA, and ED25519 keys.
func keyToPem(key crypto.PrivateKey) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}, nil
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling EC key: %w", err)
		}
		return &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: raw,
		}, nil
	case ed25519.PrivateKey:
		raw, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling ED25519 key: %w", err)
		}
		return &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: raw,
		}, nil
	}
	return nil, fmt.Errorf("unknown key type: %T", key)
}

// pemScanner returns a bufio.Scanner that splits the input into PEM blocks.
func pemScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)

	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}

		return 0, nil, nil
	})

	return scanner
}
