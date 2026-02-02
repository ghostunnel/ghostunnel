/*-
 * Copyright 2018 Square Inc.
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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/ghostunnel/ghostunnel/internal/jceks"
	"github.com/ghostunnel/ghostunnel/internal/pkcs7"
	"software.sslmate.com/src/go-pkcs12"
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

func readPEM(path, password, format string) ([]*pem.Block, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var pemBlocks []*pem.Block
	err = readAsPEMFromFiles(
		[]*os.File{file},
		format,
		func(prompt string) string { return password },
		func(block *pem.Block, format string) error {
			pemBlocks = append(pemBlocks, block)
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("error reading file '%s': %s", path, err)
	}
	if len(pemBlocks) == 0 {
		return nil, fmt.Errorf("error reading file '%s', no certificates found", path)
	}

	return pemBlocks, nil
}

func readX509(path string) ([]*x509.Certificate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	errs := []error{}
	out := []*x509.Certificate{}

	err = readAsX509FromFiles(
		[]*os.File{file}, "PEM", nil,
		func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				errs = append(errs, err)
				return nil
			}
			out = append(out, cert)
			return nil
		})
	if err != nil || len(errs) > 0 {
		return nil, fmt.Errorf("error reading file '%s'", path)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates found in file '%s'", path)
	}
	return out, nil
}

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
		return nil, errors.New("unable to read certificates from CA bundle")
	}

	return bundle, nil
}

// readAsPEMFromFiles reads PEM blocks from files, supporting PEM, DER, PKCS12, and JCEKS formats.
func readAsPEMFromFiles(files []*os.File, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		detectedFormat, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s", file.Name())
		}

		err = readCertsFromStream(reader, file.Name(), detectedFormat, password, callback)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// readAsX509FromFiles reads X.509 certificates from files, supporting PEM, DER, PKCS12, and JCEKS formats.
func readAsX509FromFiles(files []*os.File, format string, password func(string) string, callback func(*x509.Certificate, string, error) error) error {
	var errs []error
	for _, file := range files {
		reader := bufio.NewReaderSize(file, 4)
		detectedFormat, err := formatForFile(reader, file.Name(), format)
		if err != nil {
			return fmt.Errorf("unable to guess file type for file %s", file.Name())
		}

		err = readCertsFromStream(reader, file.Name(), detectedFormat, password, pemToX509(callback))
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func pemToX509(callback func(*x509.Certificate, string, error) error) func(*pem.Block, string) error {
	return func(block *pem.Block, format string) error {
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			return callback(cert, format, err)
		case "PKCS7":
			certs, err := pkcs7.ExtractCertificates(block.Bytes)
			if err != nil {
				return callback(nil, format, err)
			}
			for _, cert := range certs {
				if err := callback(cert, format, nil); err != nil {
					return err
				}
			}
		}
		return nil
	}
}

// readCertsFromStream takes some input and converts it to PEM blocks.
func readCertsFromStream(reader io.Reader, filename string, format string, password func(string) string, callback func(*pem.Block, string) error) error {
	headers := map[string]string{}
	if filename != "" && filename != os.Stdin.Name() {
		headers["originFile"] = filename
	}

	format = strings.TrimSpace(format)
	switch format {
	case "PEM":
		scanner := pemScanner(reader)
		for scanner.Scan() {
			block, _ := pem.Decode(scanner.Bytes())
			block.Headers = mergeHeaders(block.Headers, headers)
			if err := callback(block, format); err != nil {
				return err
			}
		}
		return nil
	case "DER":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s", err)
		}
		x509Certs, err0 := x509.ParseCertificates(data)
		if err0 == nil {
			for _, cert := range x509Certs {
				if err := callback(encodeX509ToPEM(cert, headers), format); err != nil {
					return err
				}
			}
			return nil
		}
		p7bBlocks, err1 := pkcs7.ParseSignedData(data)
		if err1 == nil {
			for _, block := range p7bBlocks {
				if err := callback(pkcs7ToPem(block, headers), format); err != nil {
					return err
				}
			}
			return nil
		}
		return fmt.Errorf("unable to parse certificates from DER data: X.509 parser: %s, PKCS7 parser: %s", err0, err1)
	case "PKCS12":
		data, err := io.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("unable to read input: %s", err)
		}
		blocks, err := pkcs12ToPemBlocks(data, password(""))
		if err != nil {
			return fmt.Errorf("unable to read keystore: %s", err)
		}
		if len(blocks) == 0 {
			return fmt.Errorf("keystore appears to be empty or password was incorrect")
		}
		for _, block := range blocks {
			block.Headers = mergeHeaders(block.Headers, headers)
			if err := callback(block, format); err != nil {
				return err
			}
		}
		return nil
	case "JCEKS":
		keyStore, err := jceks.LoadFromReader(reader, []byte(password("")))
		if err != nil {
			return fmt.Errorf("unable to parse keystore: %s", err)
		}
		for _, alias := range keyStore.ListCerts() {
			cert, _ := keyStore.GetCert(alias)
			if err := callback(encodeX509ToPEM(cert, mergeHeaders(headers, map[string]string{"friendlyName": alias})), format); err != nil {
				return err
			}
		}
		for _, alias := range keyStore.ListPrivateKeys() {
			key, certs, err := keyStore.GetPrivateKeyAndCerts(alias, []byte(password(alias)))
			if err != nil {
				return fmt.Errorf("unable to parse keystore: %s", err)
			}
			mergedHeaders := mergeHeaders(headers, map[string]string{"friendlyName": alias})
			block, err := keyToPem(key, mergedHeaders)
			if err != nil {
				return fmt.Errorf("problem reading key: %s", err)
			}
			if err := callback(block, format); err != nil {
				return err
			}
			for _, cert := range certs {
				if err = callback(encodeX509ToPEM(cert, mergedHeaders), format); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return fmt.Errorf("unknown file type '%s'", format)
}


func mergeHeaders(baseHeaders, extraHeaders map[string]string) map[string]string {
	headers := map[string]string{}
	for k, v := range baseHeaders {
		headers[k] = v
	}
	for k, v := range extraHeaders {
		headers[k] = v
	}
	return headers
}

func encodeX509ToPEM(cert *x509.Certificate, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "CERTIFICATE",
		Bytes:   cert.Raw,
		Headers: headers,
	}
}

func pkcs7ToPem(block *pkcs7.SignedDataEnvelope, headers map[string]string) *pem.Block {
	return &pem.Block{
		Type:    "PKCS7",
		Bytes:   block.Raw,
		Headers: headers,
	}
}

func keyToPem(key crypto.PrivateKey, headers map[string]string) (*pem.Block, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{
			Type:    "RSA PRIVATE KEY",
			Bytes:   x509.MarshalPKCS1PrivateKey(k),
			Headers: headers,
		}, nil
	case *ecdsa.PrivateKey:
		raw, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("error marshaling key: %s", reflect.TypeOf(key))
		}
		return &pem.Block{
			Type:    "EC PRIVATE KEY",
			Bytes:   raw,
			Headers: headers,
		}, nil
	}
	return nil, fmt.Errorf("unknown key type: %s", reflect.TypeOf(key))
}

// pkcs12ToPemBlocks converts all PKCS#12 safe bags in data to PEM blocks.
func pkcs12ToPemBlocks(data []byte, password string) ([]*pem.Block, error) {
	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12 data: %w", err)
	}

	var blocks []*pem.Block

	if key != nil {
		keyBlock, err := keyToPem(key, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to encode private key: %w", err)
		}
		blocks = append(blocks, keyBlock)
	}

	if cert != nil {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	}

	for _, ca := range caCerts {
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	}

	return blocks, nil
}

// formatForFile returns the file format based on flags, file extension, or magic bytes.
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

// pemScanner returns a bufio.Scanner that splits input into PEM blocks.
func pemScanner(reader io.Reader) *bufio.Scanner {
	scanner := bufio.NewScanner(reader)
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		block, rest := pem.Decode(data)
		if block != nil {
			size := len(data) - len(rest)
			return size, data[:size], nil
		}
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	})
	return scanner
}
