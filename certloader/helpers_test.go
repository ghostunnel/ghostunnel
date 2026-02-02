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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/internal/jceks"
	"github.com/ghostunnel/ghostunnel/internal/pkcs7"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ---------------------------------------------------------------------------
// formatForFile tests
// ---------------------------------------------------------------------------

func TestFormatForFileExplicitFormat(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("anything"), 4)
	format, err := formatForFile(reader, "test.xyz", "PEM")
	assert.NoError(t, err)
	assert.Equal(t, "PEM", format)
}

func TestFormatForFileByExtension(t *testing.T) {
	tests := []struct {
		filename string
		expected string
	}{
		{"cert.pem", "PEM"},
		{"cert.crt", "PEM"},
		{"cert.p7b", "PEM"},
		{"cert.p7c", "PEM"},
		{"cert.p12", "PKCS12"},
		{"cert.pfx", "PKCS12"},
		{"keystore.jceks", "JCEKS"},
		{"keystore.jks", "JCEKS"},
		{"cert.der", "DER"},
		{"cert.PEM", "PEM"},
		{"cert.P12", "PKCS12"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			reader := bufio.NewReaderSize(strings.NewReader("data data data data"), 4)
			format, err := formatForFile(reader, tt.filename, "")
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, format)
		})
	}
}

func TestFormatForFileMagicBytesPEM(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("-----BEGIN CERTIFICATE-----"), 4)
	format, err := formatForFile(reader, "noext", "")
	assert.NoError(t, err)
	assert.Equal(t, "PEM", format)
}

func TestFormatForFileMagicBytesJCEKS(t *testing.T) {
	data := []byte{0xCE, 0xCE, 0xCE, 0xCE, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	format, err := formatForFile(reader, "noext", "")
	assert.NoError(t, err)
	assert.Equal(t, "JCEKS", format)
}

func TestFormatForFileMagicBytesJKS(t *testing.T) {
	data := []byte{0xFE, 0xED, 0xFE, 0xED, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	format, err := formatForFile(reader, "noext", "")
	assert.NoError(t, err)
	assert.Equal(t, "JCEKS", format)
}

func TestFormatForFileMagicBytesDER(t *testing.T) {
	data := []byte{0x30, 0x82, 0x03, 0x00, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	format, err := formatForFile(reader, "noext", "")
	assert.NoError(t, err)
	assert.Equal(t, "DER", format)
}

func TestFormatForFileMagicBytesPKCS12(t *testing.T) {
	data := []byte{0x30, 0x82, 0x01, 0x00, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	format, err := formatForFile(reader, "noext", "")
	assert.NoError(t, err)
	assert.Equal(t, "PKCS12", format)
}

func TestFormatForFileUnknown(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	_, err := formatForFile(reader, "noext", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to guess file format")
}

func TestFormatForFileTooShort(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader("ab"), 4)
	_, err := formatForFile(reader, "noext", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read file")
}

// ---------------------------------------------------------------------------
// mergeHeaders tests
// ---------------------------------------------------------------------------

func TestMergeHeaders(t *testing.T) {
	base := map[string]string{"a": "1", "b": "2"}
	extra := map[string]string{"b": "3", "c": "4"}
	merged := mergeHeaders(base, extra)

	assert.Equal(t, "1", merged["a"])
	assert.Equal(t, "3", merged["b"]) // extra overrides base
	assert.Equal(t, "4", merged["c"])

	// Original maps should be unchanged
	assert.Equal(t, "2", base["b"])
}

func TestMergeHeadersNilMaps(t *testing.T) {
	merged := mergeHeaders(nil, nil)
	assert.NotNil(t, merged)
	assert.Empty(t, merged)
}

// ---------------------------------------------------------------------------
// keyToPem tests
// ---------------------------------------------------------------------------

func TestKeyToPemRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	headers := map[string]string{"test": "value"}
	block, err := keyToPem(key, headers)
	require.NoError(t, err)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)
	assert.Equal(t, "value", block.Headers["test"])

	_, parseErr := x509.ParsePKCS1PrivateKey(block.Bytes)
	assert.NoError(t, parseErr)
}

func TestKeyToPemECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	headers := map[string]string{"test": "value"}
	block, err := keyToPem(key, headers)
	require.NoError(t, err)
	assert.Equal(t, "EC PRIVATE KEY", block.Type)
	assert.Equal(t, "value", block.Headers["test"])

	_, parseErr := x509.ParseECPrivateKey(block.Bytes)
	assert.NoError(t, parseErr)
}

func TestKeyToPemUnknownType(t *testing.T) {
	_, err := keyToPem("not a key", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key type")
}

// ---------------------------------------------------------------------------
// encodeX509ToPEM / pkcs7ToPem tests
// ---------------------------------------------------------------------------

func TestEncodeX509ToPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	headers := map[string]string{"foo": "bar"}
	block := encodeX509ToPEM(cert, headers)

	assert.Equal(t, "CERTIFICATE", block.Type)
	assert.Equal(t, cert.Raw, block.Bytes)
	assert.Equal(t, "bar", block.Headers["foo"])
}

func TestPkcs7ToPem(t *testing.T) {
	raw := []byte{0x30, 0x82, 0x01, 0x00}
	envelope := &pkcs7.SignedDataEnvelope{Raw: asn1.RawContent(raw)}
	headers := map[string]string{"source": "test"}
	block := pkcs7ToPem(envelope, headers)

	assert.Equal(t, "PKCS7", block.Type)
	assert.Equal(t, raw, block.Bytes)
	assert.Equal(t, "test", block.Headers["source"])
}

// ---------------------------------------------------------------------------
// readCertsFromStream — PEM tests
// ---------------------------------------------------------------------------

func TestReadCertsFromStreamUnknownFormat(t *testing.T) {
	reader := strings.NewReader("data")
	err := readCertsFromStream(reader, "test.bin", "UNKNOWN", nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown file type")
}

func TestReadCertsFromStreamSetsOriginFileHeader(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	var headers map[string]string
	err := readCertsFromStream(
		bytes.NewReader(pemData), "/path/to/cert.pem", "PEM", nil,
		func(block *pem.Block, format string) error {
			headers = block.Headers
			return nil
		},
	)
	require.NoError(t, err)
	assert.Equal(t, "/path/to/cert.pem", headers["originFile"])
}

func TestReadCertsFromStreamNoOriginForEmptyFilename(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	var headers map[string]string
	err := readCertsFromStream(
		bytes.NewReader(pemData), "", "PEM", nil,
		func(block *pem.Block, format string) error {
			headers = block.Headers
			return nil
		},
	)
	require.NoError(t, err)
	_, hasOrigin := headers["originFile"]
	assert.False(t, hasOrigin)
}

func TestReadCertsFromStreamNoOriginForStdin(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	var headers map[string]string
	err := readCertsFromStream(
		bytes.NewReader(pemData), os.Stdin.Name(), "PEM", nil,
		func(block *pem.Block, format string) error {
			headers = block.Headers
			return nil
		},
	)
	require.NoError(t, err)
	_, hasOrigin := headers["originFile"]
	assert.False(t, hasOrigin)
}

func TestReadCertsFromStreamCallbackError(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	callbackErr := errors.New("callback failed")
	err := readCertsFromStream(
		bytes.NewReader(pemData), "test.pem", "PEM", nil,
		func(block *pem.Block, format string) error { return callbackErr },
	)
	assert.ErrorIs(t, err, callbackErr)
}

// ---------------------------------------------------------------------------
// readCertsFromStream — DER tests
// ---------------------------------------------------------------------------

func TestReadCertsFromStreamDERValid(t *testing.T) {
	cert := generateSelfSignedCert(t)

	var blocks []*pem.Block
	err := readCertsFromStream(
		bytes.NewReader(cert.Raw), "test.der", "DER", nil,
		func(block *pem.Block, format string) error {
			blocks = append(blocks, block)
			return nil
		},
	)
	require.NoError(t, err)
	assert.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}

func TestReadCertsFromStreamDERInvalid(t *testing.T) {
	err := readCertsFromStream(
		bytes.NewReader([]byte("not valid DER")), "test.der", "DER", nil,
		func(block *pem.Block, format string) error { return nil },
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse certificates from DER data")
}

func TestReadCertsFromStreamDERCallbackError(t *testing.T) {
	cert := generateSelfSignedCert(t)
	callbackErr := errors.New("der callback failed")

	err := readCertsFromStream(
		bytes.NewReader(cert.Raw), "test.der", "DER", nil,
		func(block *pem.Block, format string) error { return callbackErr },
	)
	assert.ErrorIs(t, err, callbackErr)
}

// ---------------------------------------------------------------------------
// readCertsFromStream — PKCS12 tests
// ---------------------------------------------------------------------------

func TestReadCertsFromStreamPKCS12Valid(t *testing.T) {
	p12Data := generatePKCS12(t, "testpass")

	var blocks []*pem.Block
	err := readCertsFromStream(
		bytes.NewReader(p12Data), "test.p12", "PKCS12",
		func(string) string { return "testpass" },
		func(block *pem.Block, format string) error {
			blocks = append(blocks, block)
			return nil
		},
	)
	require.NoError(t, err)
	assert.NotEmpty(t, blocks)

	// Should have at least a cert and a key
	var hasCert, hasKey bool
	for _, b := range blocks {
		if b.Type == "CERTIFICATE" {
			hasCert = true
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			hasKey = true
		}
	}
	assert.True(t, hasCert, "PKCS12 should contain a certificate")
	assert.True(t, hasKey, "PKCS12 should contain a private key")
}

func TestReadCertsFromStreamPKCS12InvalidPassword(t *testing.T) {
	p12Data := generatePKCS12(t, "correctpass")

	err := readCertsFromStream(
		bytes.NewReader(p12Data), "test.p12", "PKCS12",
		func(string) string { return "wrongpass" },
		func(block *pem.Block, format string) error { return nil },
	)
	assert.Error(t, err)
}

func TestReadCertsFromStreamPKCS12InvalidData(t *testing.T) {
	err := readCertsFromStream(
		bytes.NewReader([]byte("not pkcs12 data")), "test.p12", "PKCS12",
		func(string) string { return "" },
		func(block *pem.Block, format string) error { return nil },
	)
	assert.Error(t, err)
}

func TestReadCertsFromStreamPKCS12CallbackError(t *testing.T) {
	p12Data := generatePKCS12(t, "testpass")
	callbackErr := errors.New("p12 callback failed")

	err := readCertsFromStream(
		bytes.NewReader(p12Data), "test.p12", "PKCS12",
		func(string) string { return "testpass" },
		func(block *pem.Block, format string) error { return callbackErr },
	)
	assert.ErrorIs(t, err, callbackErr)
}

func TestReadCertsFromStreamPKCS12SetsHeaders(t *testing.T) {
	p12Data := generatePKCS12(t, "testpass")

	var headers []map[string]string
	err := readCertsFromStream(
		bytes.NewReader(p12Data), "my.p12", "PKCS12",
		func(string) string { return "testpass" },
		func(block *pem.Block, format string) error {
			headers = append(headers, block.Headers)
			return nil
		},
	)
	require.NoError(t, err)
	for _, h := range headers {
		assert.Equal(t, "my.p12", h["originFile"])
	}
}

// ---------------------------------------------------------------------------
// readCertsFromStream — JCEKS tests
// ---------------------------------------------------------------------------

func TestReadCertsFromStreamJCEKSWithCert(t *testing.T) {
	cert := generateSelfSignedCert(t)
	jceksData := generateJCEKSWithCert(t, cert, "testpassword")

	var blocks []*pem.Block
	err := readCertsFromStream(
		bytes.NewReader(jceksData), "test.jceks", "JCEKS",
		func(string) string { return "testpassword" },
		func(block *pem.Block, format string) error {
			blocks = append(blocks, block)
			return nil
		},
	)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
	assert.Equal(t, cert.Raw, blocks[0].Bytes)
	assert.Equal(t, "mycert", blocks[0].Headers["friendlyName"])
}

func TestReadCertsFromStreamJCEKSInvalid(t *testing.T) {
	err := readCertsFromStream(
		bytes.NewReader([]byte("not jceks")), "test.jceks", "JCEKS",
		func(string) string { return "" },
		func(block *pem.Block, format string) error { return nil },
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse keystore")
}

func TestReadCertsFromStreamJCEKSCallbackError(t *testing.T) {
	cert := generateSelfSignedCert(t)
	jceksData := generateJCEKSWithCert(t, cert, "testpassword")
	callbackErr := errors.New("jceks callback failed")

	err := readCertsFromStream(
		bytes.NewReader(jceksData), "test.jceks", "JCEKS",
		func(string) string { return "testpassword" },
		func(block *pem.Block, format string) error { return callbackErr },
	)
	assert.ErrorIs(t, err, callbackErr)
}

// ---------------------------------------------------------------------------
// pkcs12ToPemBlocks tests
// ---------------------------------------------------------------------------

func TestPkcs12ToPemBlocksRSA(t *testing.T) {
	p12Data := generatePKCS12(t, "pass")
	blocks, err := pkcs12ToPemBlocks(p12Data, "pass")
	require.NoError(t, err)
	require.NotEmpty(t, blocks)

	for _, b := range blocks {
		assert.NotEqual(t, "PRIVATE KEY", b.Type, "generic PRIVATE KEY should be rewritten to specific type")
	}
}

func TestPkcs12ToPemBlocksInvalidData(t *testing.T) {
	_, err := pkcs12ToPemBlocks([]byte("garbage"), "pass")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse PKCS#12 data")
}

func TestPkcs12ToPemBlocksWrongPassword(t *testing.T) {
	p12Data := generatePKCS12(t, "correct")
	_, err := pkcs12ToPemBlocks(p12Data, "wrong")
	assert.Error(t, err)
}

func TestPkcs12ToPemBlocksEC(t *testing.T) {
	p12Data := generatePKCS12EC(t, "pass")
	blocks, err := pkcs12ToPemBlocks(p12Data, "pass")
	require.NoError(t, err)

	var hasECKey bool
	for _, b := range blocks {
		if b.Type == "EC PRIVATE KEY" {
			hasECKey = true
		}
	}
	assert.True(t, hasECKey, "should contain EC PRIVATE KEY block")
}

// ---------------------------------------------------------------------------
// pemToX509 tests
// ---------------------------------------------------------------------------

func TestPemToX509SkipsNonCertBlocks(t *testing.T) {
	var certs []*x509.Certificate
	callback := pemToX509(func(cert *x509.Certificate, format string, err error) error {
		if err == nil {
			certs = append(certs, cert)
		}
		return nil
	})

	err := callback(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")}, "PEM")
	assert.NoError(t, err)
	assert.Empty(t, certs)
}

func TestPemToX509ParsesCert(t *testing.T) {
	cert := generateSelfSignedCert(t)
	var parsedCerts []*x509.Certificate
	callback := pemToX509(func(c *x509.Certificate, format string, err error) error {
		if err != nil {
			return err
		}
		parsedCerts = append(parsedCerts, c)
		return nil
	})

	err := callback(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}, "PEM")
	assert.NoError(t, err)
	assert.Len(t, parsedCerts, 1)
}

func TestPemToX509InvalidCertData(t *testing.T) {
	var gotErr error
	callback := pemToX509(func(c *x509.Certificate, format string, err error) error {
		gotErr = err
		return nil
	})

	err := callback(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}, "PEM")
	assert.NoError(t, err) // callback doesn't return the error
	assert.Error(t, gotErr, "should pass parse error to callback")
}

func TestPemToX509PKCS7Block(t *testing.T) {
	// Build a minimal PKCS7 SignedData structure containing a certificate
	cert := generateSelfSignedCert(t)
	p7Data := buildPKCS7SignedData(t, cert)

	var parsedCerts []*x509.Certificate
	callback := pemToX509(func(c *x509.Certificate, format string, err error) error {
		if err != nil {
			return err
		}
		parsedCerts = append(parsedCerts, c)
		return nil
	})

	err := callback(&pem.Block{Type: "PKCS7", Bytes: p7Data}, "PEM")
	assert.NoError(t, err)
	assert.Len(t, parsedCerts, 1)
}

func TestPemToX509PKCS7InvalidData(t *testing.T) {
	var gotErr error
	callback := pemToX509(func(c *x509.Certificate, format string, err error) error {
		gotErr = err
		return err
	})

	err := callback(&pem.Block{Type: "PKCS7", Bytes: []byte("bad")}, "PEM")
	assert.Error(t, err)
	assert.Error(t, gotErr)
}

// ---------------------------------------------------------------------------
// readAsPEMFromFiles / readAsX509FromFiles tests
// ---------------------------------------------------------------------------

func TestReadAsPEMFromFilesFormatGuessError(t *testing.T) {
	// Create a file with unknown content and no recognized extension
	f, err := os.CreateTemp("", "ghostunnel-test-noext")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write([]byte("ab"))
	require.NoError(t, err)
	f.Close()

	file, err := os.Open(f.Name())
	require.NoError(t, err)
	defer file.Close()

	err = readAsPEMFromFiles(
		[]*os.File{file}, "", nil,
		func(block *pem.Block, format string) error { return nil },
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to guess file type")
}

func TestReadAsX509FromFilesFormatGuessError(t *testing.T) {
	f, err := os.CreateTemp("", "ghostunnel-test-noext")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write([]byte("ab"))
	require.NoError(t, err)
	f.Close()

	file, err := os.Open(f.Name())
	require.NoError(t, err)
	defer file.Close()

	err = readAsX509FromFiles(
		[]*os.File{file}, "", nil,
		func(cert *x509.Certificate, format string, err error) error { return nil },
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to guess file type")
}

func TestReadAsX509FromFilesPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	f, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write(pemData)
	require.NoError(t, err)
	f.Close()

	file, err := os.Open(f.Name())
	require.NoError(t, err)
	defer file.Close()

	var certs []*x509.Certificate
	err = readAsX509FromFiles(
		[]*os.File{file}, "PEM", nil,
		func(c *x509.Certificate, format string, err error) error {
			if err == nil {
				certs = append(certs, c)
			}
			return nil
		},
	)
	require.NoError(t, err)
	assert.Len(t, certs, 1)
}

// ---------------------------------------------------------------------------
// readPEM tests
// ---------------------------------------------------------------------------

func TestReadPEMMultipleCerts(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	doublePEM := append(pemData, pemData...)

	f, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write(doublePEM)
	require.NoError(t, err)
	f.Close()

	blocks, err := readPEM(f.Name(), "", "PEM")
	assert.NoError(t, err)
	assert.Len(t, blocks, 2)
}

func TestReadPEMFromPKCS12File(t *testing.T) {
	p12Data := generatePKCS12(t, "pass")

	f, err := os.CreateTemp("", "ghostunnel-test-*.p12")
	require.NoError(t, err)
	defer os.Remove(f.Name())
	_, err = f.Write(p12Data)
	require.NoError(t, err)
	f.Close()

	// Empty format triggers auto-detect; .p12 extension -> PKCS12
	blocks, err := readPEM(f.Name(), "pass", "")
	require.NoError(t, err)
	assert.NotEmpty(t, blocks)
}

// ---------------------------------------------------------------------------
// connectproxy write-error path is covered in its own package
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Test helpers — generate fixtures
// ---------------------------------------------------------------------------

// generateSelfSignedCert creates a minimal self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert
}

// generateSelfSignedCertAndKey creates a cert + RSA key pair.
func generateSelfSignedCertAndKey(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert, key
}

// generateSelfSignedCertAndECKey creates a cert + ECDSA key pair.
func generateSelfSignedCertAndECKey(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(derBytes)
	require.NoError(t, err)
	return cert, key
}

// generatePKCS12 creates a PKCS12 keystore with an RSA key+cert.
func generatePKCS12(t *testing.T, password string) []byte {
	t.Helper()
	cert, key := generateSelfSignedCertAndKey(t)

	p12Data, err := gopkcs12.Encode(rand.Reader, key, cert, nil, password)
	require.NoError(t, err)
	return p12Data
}

// generatePKCS12EC creates a PKCS12 keystore with an ECDSA key+cert.
func generatePKCS12EC(t *testing.T, password string) []byte {
	t.Helper()
	cert, key := generateSelfSignedCertAndECKey(t)

	p12Data, err := gopkcs12.Encode(rand.Reader, key, cert, nil, password)
	require.NoError(t, err)
	return p12Data
}

// generateJCEKSWithCert creates a JCEKS keystore containing a single trusted certificate.
func generateJCEKSWithCert(t *testing.T, cert *x509.Certificate, password string) []byte {
	t.Helper()
	var enc jceks.Encoder
	err := enc.SetIntegrityPassword(password)
	require.NoError(t, err)

	err = enc.AddTrustedCertificate("mycert", time.Now(), cert.Raw)
	require.NoError(t, err)

	var buf bytes.Buffer
	_, err = enc.WriteTo(&buf)
	require.NoError(t, err)
	return buf.Bytes()
}

// buildPKCS7SignedData constructs a minimal PKCS#7 SignedData ASN.1 structure
// containing the given certificate.
func buildPKCS7SignedData(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()

	// SignedData ::= SEQUENCE {
	//   version INTEGER,
	//   digestAlgorithms SET OF,
	//   contentInfo ContentInfo,
	//   certificates [0] IMPLICIT SET OF Certificate OPTIONAL,
	//   ...
	//   signerInfos SET OF
	// }

	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
	}

	type signedData struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      contentInfo
		Certificates     asn1.RawValue `asn1:"tag:0,optional,set"`
		SignerInfos      asn1.RawValue
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: asn1.TagSet, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
		ContentInfo:      contentInfo{ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}},
		Certificates:     asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      asn1.RawValue{Tag: asn1.TagSet, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
	}

	sdBytes, err := asn1.Marshal(sd)
	require.NoError(t, err)

	// Wrap sdBytes in an explicit context-specific [0] tag
	wrappedSD := asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, IsCompound: true, Bytes: sdBytes}

	type envelope struct {
		Type       asn1.ObjectIdentifier
		SignedData asn1.RawValue
	}

	env := envelope{
		Type:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		SignedData: wrappedSD,
	}

	result, err := asn1.Marshal(env)
	require.NoError(t, err)
	return result
}
