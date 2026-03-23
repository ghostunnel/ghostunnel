/*-
 * Copyright Ghostunnel contributors.
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
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

// errReader is an io.Reader that always returns an error.
type errReader struct{ err error }

func (r *errReader) Read([]byte) (int, error) { return 0, r.err }

func TestReadPKCS12ED25519(t *testing.T) {
	// Generate an ED25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ed25519-test",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Encode as PKCS#12
	password := "test-password"
	pfxData, err := pkcs12.Modern2023.Encode(priv, cert, nil, password)
	require.NoError(t, err)

	// Write to temp file
	tmpFile, err := os.CreateTemp("", "ghostunnel-test-*.p12")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.Write(pfxData)
	require.NoError(t, err)
	tmpFile.Close()

	// Read back using our readPEM function
	blocks, err := readPEM(tmpFile.Name(), password, "")
	assert.NoError(t, err, "should read PKCS#12 file with ED25519 key")
	assert.NotEmpty(t, blocks, "should have PEM blocks")

	// Verify we got a private key and a certificate
	var hasPrivateKey, hasCertificate bool
	for _, block := range blocks {
		if block.Type == "PRIVATE KEY" {
			hasPrivateKey = true
			// Verify the key can be parsed back
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			assert.NoError(t, err, "should parse PKCS#8 private key")
			_, ok := key.(ed25519.PrivateKey)
			assert.True(t, ok, "should be an ED25519 key")
		}
		if block.Type == "CERTIFICATE" {
			hasCertificate = true
		}
	}
	assert.True(t, hasPrivateKey, "should contain a private key")
	assert.True(t, hasCertificate, "should contain a certificate")
}

func TestKeyToPemED25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	block, err := keyToPem(priv)
	assert.NoError(t, err)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Verify round-trip
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)
	_, ok := key.(ed25519.PrivateKey)
	assert.True(t, ok)
}

func TestKeyToPemUnknownType(t *testing.T) {
	_, err := keyToPem("not a key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown key type")
}

// TestPrivateKeyInfoED25519RoundTrip verifies that the privateKeyInfo struct
// (used by JCEKS Recover) produces valid PKCS#8 DER when marshaled with asn1.Marshal,
// and that x509.ParsePKCS8PrivateKey can parse it back to an ed25519.PrivateKey.
func TestPrivateKeyInfoED25519RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Build a privateKeyInfo struct matching the JCEKS internal type.
	// This is the same struct shape as Go's crypto/x509 pkcs8 struct.
	type privateKeyInfo struct {
		Version    int
		Algo       pkix.AlgorithmIdentifier
		PrivateKey []byte
	}

	// ED25519 PKCS#8 wraps the seed in an OCTET STRING
	seed := priv.Seed()
	wrappedSeed, err := asn1.Marshal(seed)
	require.NoError(t, err)

	pki := privateKeyInfo{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 3, 101, 112}, // id-EdDSA / ED25519
		},
		PrivateKey: wrappedSeed,
	}

	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	// Parse it back
	key, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
	require.NoError(t, err)

	recovered, ok := key.(ed25519.PrivateKey)
	require.True(t, ok, "expected ed25519.PrivateKey, got %T", key)
	assert.Equal(t, priv.Seed(), recovered.Seed(), "recovered key seed should match original")
}

// --- keyToPem RSA/ECDSA tests ---

func TestKeyToPemRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	block, err := keyToPem(key)
	require.NoError(t, err)
	assert.Equal(t, "RSA PRIVATE KEY", block.Type)

	recovered, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, key.D.Bytes(), recovered.D.Bytes())
}

func TestKeyToPemECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	block, err := keyToPem(key)
	require.NoError(t, err)
	assert.Equal(t, "EC PRIVATE KEY", block.Type)

	recovered, err := x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, key.D.Bytes(), recovered.D.Bytes())
}

// --- readDERBlocks tests ---

func generateSelfSignedCertDER(t *testing.T) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "der-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)
	return certDER
}

func TestReadDERBlocksX509(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	blocks, err := readDERBlocks(bytes.NewReader(certDER))
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)

	cert, err := x509.ParseCertificate(blocks[0].Bytes)
	require.NoError(t, err)
	assert.Equal(t, "der-test", cert.Subject.CommonName)
}

func TestReadDERBlocksPKCS7(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	// Build a minimal PKCS#7 SignedData envelope in DER format
	signedData := struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		ContentInfo      asn1.RawValue
		Certificates     []asn1.RawValue `asn1:"tag:0,optional,set"`
		SignerInfos      asn1.RawValue   `asn1:"set"`
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
		ContentInfo:      asn1.RawValue{FullBytes: mustMarshalASN1(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})},
		Certificates:     []asn1.RawValue{{FullBytes: certDER}},
		SignerInfos:      asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
	}

	envelope := struct {
		Type       asn1.ObjectIdentifier
		SignedData interface{} `asn1:"tag:0,explicit,optional"`
	}{
		Type:       asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2},
		SignedData: signedData,
	}

	p7Data, err := asn1.Marshal(envelope)
	require.NoError(t, err)

	blocks, err := readDERBlocks(bytes.NewReader(p7Data))
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "PKCS7", blocks[0].Type)
}

func TestReadDERBlocksInvalid(t *testing.T) {
	garbage := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	_, err := readDERBlocks(bytes.NewReader(garbage))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "X.509 parser gave")
	assert.Contains(t, err.Error(), "PKCS7 parser gave")
}

// --- readCertsFromStream tests ---

func TestReadCertsFromStreamDER(t *testing.T) {
	certDER := generateSelfSignedCertDER(t)

	blocks, err := readCertsFromStream(bytes.NewReader(certDER), "DER", "")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}

func TestReadCertsFromStreamJCEKS(t *testing.T) {
	// Build a minimal JCEKS with a trusted cert
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jceks-stream-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	jceksData := buildMinimalJCEKSForDecode(t, "alias", certDER, password)

	blocks, err := readCertsFromStream(bytes.NewReader(jceksData), "JCEKS", password)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}

func TestReadCertsFromStreamUnknown(t *testing.T) {
	_, err := readCertsFromStream(bytes.NewReader([]byte("data")), "BOGUS", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown file type")
}

// buildMinimalJCEKSForDecode constructs a JCEKS binary for use in decode_test.go.
func buildMinimalJCEKSForDecode(t *testing.T, alias string, certDER []byte, password string) []byte {
	t.Helper()

	const jceksMagic = 0xcececece
	const jceksVersion = 0x02
	const trustedCertEntryTag uint32 = 2
	const jceksIntegrityMagic = "Mighty Aphrodite"

	// Encode integrity password (big-endian UTF-16)
	var encodedPassword []byte
	for _, r := range password {
		encodedPassword = binary.BigEndian.AppendUint16(encodedPassword, uint16(r))
	}

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, trustedCertEntryTag))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err := body.WriteString(alias)
	require.NoError(t, err)
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))
	certType := "X.509"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(certType))))
	_, err = body.WriteString(certType)
	require.NoError(t, err)
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(certDER))))
	_, err = body.Write(certDER)
	require.NoError(t, err)

	h := sha1.New()
	h.Write(encodedPassword)
	h.Write([]byte(jceksIntegrityMagic))
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

func mustMarshalASN1(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(v)
	require.NoError(t, err)
	return data
}

// --- readJCEKSBlocks tests ---

func TestReadJCEKSBlocksTrustedCert(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jceks-blocks-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	jceksData := buildMinimalJCEKSForDecode(t, "alias", certDER, password)

	blocks, err := readJCEKSBlocks(bytes.NewReader(jceksData), password)
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)

	cert, err := x509.ParseCertificate(blocks[0].Bytes)
	require.NoError(t, err)
	assert.Equal(t, "jceks-blocks-test", cert.Subject.CommonName)
}

func TestReadJCEKSBlocksError(t *testing.T) {
	_, err := readJCEKSBlocks(bytes.NewReader([]byte{0x00, 0x00}), "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse keystore")
}

// --- formatForFile additional tests ---

func TestFormatDetectionDERMagicBytes(t *testing.T) {
	// 0x30 0x82 0x03 XX → DER (the 0x03 in third byte triggers DER detection)
	derData := []byte{0x30, 0x82, 0x03, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(derData), 4)
	result, err := formatForFile(reader, "", "")
	assert.NoError(t, err)
	assert.Equal(t, "DER", result)
}

func TestFormatDetectionPKCS12MagicBytes(t *testing.T) {
	// 0x30 0x82 0x00 XX → PKCS12 (the third byte is not 0x03)
	p12Data := []byte{0x30, 0x82, 0x00, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(p12Data), 4)
	result, err := formatForFile(reader, "", "")
	assert.NoError(t, err)
	assert.Equal(t, "PKCS12", result)
}

func TestFormatDetectionPeekError(t *testing.T) {
	// Reader with fewer than 4 bytes and no extension → peek error
	reader := bufio.NewReaderSize(bytes.NewReader([]byte{0x01}), 4)
	_, err := formatForFile(reader, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read file")
}

func TestFormatDetectionUnknownMagic(t *testing.T) {
	// Non-matching magic bytes, no extension
	data := []byte{0x00, 0x00, 0x00, 0x00}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	_, err := formatForFile(reader, "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to guess file format")
}

// --- readPKCS12Blocks additional tests ---

func TestReadPKCS12BlocksInvalidData(t *testing.T) {
	_, err := readPKCS12Blocks(bytes.NewReader([]byte("not-valid-pkcs12")), "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read keystore")
}

func TestReadPKCS12BlocksWithCACerts(t *testing.T) {
	// Generate a CA key + cert
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	// Generate a leaf key + cert signed by CA
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafCertDER)
	require.NoError(t, err)

	// Encode as PKCS#12 with CA cert
	password := "test-password"
	pfxData, err := pkcs12.Modern2023.Encode(leafKey, leafCert, []*x509.Certificate{caCert}, password)
	require.NoError(t, err)

	blocks, err := readPKCS12Blocks(bytes.NewReader(pfxData), password)
	require.NoError(t, err)

	// Should have: 1 private key + 1 leaf cert + 1 CA cert = 3 blocks
	require.Len(t, blocks, 3)

	var keyCount, certCount int
	for _, block := range blocks {
		switch block.Type {
		case "EC PRIVATE KEY":
			keyCount++
		case "CERTIFICATE":
			certCount++
		}
	}
	assert.Equal(t, 1, keyCount, "should have 1 private key")
	assert.Equal(t, 2, certCount, "should have 2 certificates (leaf + CA)")
}

func TestFormatDetection(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		filename string
		format   string
		expected string
	}{
		{"explicit format", []byte("----"), "test.txt", "PEM", "PEM"},
		{"pem extension", []byte("----"), "test.pem", "", "PEM"},
		{"crt extension", []byte("----"), "test.crt", "", "PEM"},
		{"p12 extension", []byte("----"), "test.p12", "", "PKCS12"},
		{"pfx extension", []byte("----"), "test.pfx", "", "PKCS12"},
		{"jceks extension", []byte("----"), "test.jceks", "", "JCEKS"},
		{"jks extension", []byte("----"), "test.jks", "", "JCEKS"},
		{"der extension", []byte("----"), "test.der", "", "DER"},
		{"magic bytes JCEKS", []byte{0xCE, 0xCE, 0xCE, 0xCE}, "", "", "JCEKS"},
		{"magic bytes JKS", []byte{0xFE, 0xED, 0xFE, 0xED}, "", "", "JCEKS"},
		{"magic bytes PEM", []byte("----"), "", "", "PEM"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := bufio.NewReaderSize(bytes.NewReader(tt.data), 4)
			result, err := formatForFile(reader, tt.filename, tt.format)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// --- IO error tests ---

func TestReadDERBlocksIOError(t *testing.T) {
	_, err := readDERBlocks(&errReader{errors.New("disk failure")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read input")
}

func TestReadPKCS12BlocksIOError(t *testing.T) {
	_, err := readPKCS12Blocks(&errReader{errors.New("disk failure")}, "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to read input")
}

func TestReadJCEKSBlocksGetPrivateKeyError(t *testing.T) {
	// Build a JCEKS with a private key entry whose protectedKey is invalid ASN.1.
	// This causes Recover to fail, which readJCEKSBlocks should propagate.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	// Build a JCEKS with a private key entry using garbage as the encrypted key
	jceksData := buildJCEKSWithPrivateKeyForDecode(t, "badkey", []byte{0x01, 0x02}, certDER, password)

	_, err = readJCEKSBlocks(bytes.NewReader(jceksData), password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse keystore")
}

// buildJCEKSWithPrivateKeyForDecode constructs a JCEKS binary containing one private key entry.
func buildJCEKSWithPrivateKeyForDecode(t *testing.T, alias string, encryptedKeyDER []byte, certDER []byte, password string) []byte {
	t.Helper()

	const jceksMagic = 0xcececece
	const jceksVersion = 0x02
	const privateKeyEntryTag uint32 = 1
	const jceksIntegrityMagic = "Mighty Aphrodite"

	var encodedPassword []byte
	for _, r := range password {
		encodedPassword = binary.BigEndian.AppendUint16(encodedPassword, uint16(r))
	}

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, privateKeyEntryTag))

	// Alias
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err := body.WriteString(alias)
	require.NoError(t, err)

	// Timestamp
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

	// Encrypted key bytes
	require.NoError(t, binary.Write(&body, binary.BigEndian, int32(len(encryptedKeyDER))))
	_, err = body.Write(encryptedKeyDER)
	require.NoError(t, err)

	// Certificate count: 1
	require.NoError(t, binary.Write(&body, binary.BigEndian, int32(1)))

	// Certificate
	certType := "X.509"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(certType))))
	_, err = body.WriteString(certType)
	require.NoError(t, err)
	require.NoError(t, binary.Write(&body, binary.BigEndian, int32(len(certDER))))
	_, err = body.Write(certDER)
	require.NoError(t, err)

	// Integrity hash
	h := sha1.New()
	h.Write(encodedPassword)
	h.Write([]byte(jceksIntegrityMagic))
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

func TestFormatDetectionP7bExtension(t *testing.T) {
	reader := bufio.NewReaderSize(bytes.NewReader([]byte("----")), 4)
	result, err := formatForFile(reader, "test.p7b", "")
	assert.NoError(t, err)
	assert.Equal(t, "PEM", result)
}

func TestFormatDetectionP7cExtension(t *testing.T) {
	reader := bufio.NewReaderSize(bytes.NewReader([]byte("----")), 4)
	result, err := formatForFile(reader, "test.p7c", "")
	assert.NoError(t, err)
	assert.Equal(t, "PEM", result)
}

func TestFormatDetectionCONNMagic(t *testing.T) {
	// 0x434f4e4e = "CONN" → PEM detection
	data := []byte{0x43, 0x4f, 0x4e, 0x4e}
	reader := bufio.NewReaderSize(bytes.NewReader(data), 4)
	result, err := formatForFile(reader, "", "")
	assert.NoError(t, err)
	assert.Equal(t, "PEM", result)
}

func TestReadCertsFromStreamPEM(t *testing.T) {
	pemData := []byte(`-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIJAPjKcAKZMSkUMA0GCSqGSIb3DQEBCwUAMCMxEjAQBgNV
BAMTCWxvY2FsaG9zdDENMAsGA1UECxMEdGVzdDAeFw0xNTEwMDcxODExNTlaFw0x
NjEwMDYxODExNTlaMCMxEjAQBgNVBAMTCWxvY2FsaG9zdDENMAsGA1UECxMEdGVz
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4EbZf3EMb/ciW5nGlN
yrf5Pcfz3ZnjWRy1kvBriuPD6NQSZaTWTPmJnbdS/Q5FH0p/6ZjdZKXf6f7WNnAz
JwW0XK7NT3N2DrWfgQqrrVvLAYlfqgHnC7Fxqq7FCpgWjf7L8wcQXfdIYkhdsE4n
osLmCRvx7qS+wuasb6nLzBtg7b99ZvO8K/sezrDIjwzemBWA1Vovztw/vGD4J4/h
D0hiOOqFGWstwFxB9oG4d/QJ45VttLMGuiZCY+A4IyBgPCxphrEec6zf8H4u/ceQ
bB8i1IMmD1VTsq9afeVhMKuoSn2Bs3VRB6c9FpL41/ftN5mYpZCteZH+qQ/DhK/y
Dz0CAwEAAaNfMF0wDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAqwwHQYDVR0lBBYw
FAYIKwYBBQUHAwIGCCsGAQUFBwMBMCEGA1UdEQQaMBiHBH8AAAGHEAAAAAAAAAAA
AAAAAAAAAAEwDQYJKoZIhvcNAQELBQADggEBABuBe5cuyZy6StCYebI3FLN3CEla
/3Hreul6i5giqkF90X6M+9eERZCqSqm2whBMSF4vG+1B6GX1K6S29PUOmTDWyasW
B0WlBgRiZld3JfFBuJu6xk1a8+XwwlGOgEsggepjkrAXbjbqnUMAKOJkjFIyIPvk
5p97SYDJYiOh7MmjyXUIzyNdqpL5WiUgKPTxXL+1tNzxH1jjxfVdjaNaNcOJuu20
9tsMqDZyTm2yZWOBUXbtqlaMQHrs5Ksz5EKk5/U5KfJehKss8oba2npg/6echTJU
nkOOZ6U4eEju7H1S46qlN9ZmUmSrrjwec3H7CnvxQ0ncEyZXlEiTlbO2JQI=
-----END CERTIFICATE-----`)

	blocks, err := readCertsFromStream(bytes.NewReader(pemData), " PEM ", "")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}
