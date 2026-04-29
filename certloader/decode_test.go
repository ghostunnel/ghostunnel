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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"

	"github.com/ghostunnel/ghostunnel/certloader/jceks/jcekstest"
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

	// Read back using our readCertificateFile function
	blocks, err := readCertificateFile(tmpFile.Name(), password, "")
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

	block, err := keyToPEM(priv)
	assert.NoError(t, err)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	// Verify round-trip
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err)
	_, ok := key.(ed25519.PrivateKey)
	assert.True(t, ok)
}

func TestKeyToPemUnknownType(t *testing.T) {
	_, err := keyToPEM("not a key")
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

// --- keyToPEM RSA/ECDSA tests ---

func TestKeyToPemRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	block, err := keyToPEM(key)
	require.NoError(t, err)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	recovered, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	rsaKey, ok := recovered.(*rsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, key.D.Bytes(), rsaKey.D.Bytes())
}

func TestKeyToPemECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	block, err := keyToPEM(key)
	require.NoError(t, err)
	assert.Equal(t, "PRIVATE KEY", block.Type)

	recovered, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	require.NoError(t, err)
	ecKey, ok := recovered.(*ecdsa.PrivateKey)
	require.True(t, ok)
	assert.Equal(t, key.D.Bytes(), ecKey.D.Bytes())
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

	// Build a PKCS#7 SignedData envelope using the smallstep library
	p7Data, err := pkcs7.DegenerateCertificate(certDER)
	require.NoError(t, err)

	blocks, err := readDERBlocks(bytes.NewReader(p7Data))
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}

func TestReadDERBlocksInvalid(t *testing.T) {
	garbage := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	_, err := readDERBlocks(bytes.NewReader(garbage))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse DER data as X.509")
	assert.Contains(t, err.Error(), "or PKCS7")
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
	jceksData := jcekstest.BuildMinimalJCEKS(t, "alias", certDER, password)

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
	jceksData := jcekstest.BuildMinimalJCEKS(t, "alias", certDER, password)

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
		case "PRIVATE KEY":
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

func TestReadJCEKSBlocksWrongPassword(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "wrong-pw"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	jceksData := jcekstest.BuildMinimalJCEKS(t, "alias", certDER, "correct-password")

	_, err = readJCEKSBlocks(bytes.NewReader(jceksData), "wrong-password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to parse keystore")
}

func TestReadJCEKSBlocksCorruptCipher(t *testing.T) {
	type encryptedPrivateKeyInfo struct {
		Algo         pkix.AlgorithmIdentifier
		EncryptedKey []byte
	}
	oidPBEWithMD5AndDES3CBC := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
	envelope := encryptedPrivateKeyInfo{
		Algo:         pkix.AlgorithmIdentifier{Algorithm: oidPBEWithMD5AndDES3CBC},
		EncryptedKey: bytes.Repeat([]byte{0xAA}, 32),
	}
	encDER, err := asn1.Marshal(envelope)
	require.NoError(t, err)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "corrupt"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	jceksData := jcekstest.BuildJCEKSWithPrivateKey(t, "corruptkey", encDER, certDER, password)

	_, err = readJCEKSBlocks(bytes.NewReader(jceksData), password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to recover private key 'corruptkey'")
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
	jceksData := jcekstest.BuildJCEKSWithPrivateKey(t, "badkey", []byte{0x01, 0x02}, certDER, password)

	_, err = readJCEKSBlocks(bytes.NewReader(jceksData), password)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to recover private key 'badkey'")
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

	blocks, err := readCertsFromStream(bytes.NewReader(pemData), "PEM", "")
	require.NoError(t, err)
	require.Len(t, blocks, 1)
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
}

func TestReadPEMBlocksInterleavedText(t *testing.T) {
	// CA bundles often have human-readable text between PEM blocks.
	pemData := []byte(`Some human-readable description of cert 1
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh2wL8MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3QxMB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowETEPMA0GA1UEAwwG
dGVzdDEwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0Z3VS5JJcds3xf0gSfLEtEjn
Muqy+97YHUBzBKAFMnb8NSOqCjrfBfRkzgEiXsAy+D/UCHfaAT6JxVwrZJwG7wID
AQABo1MwUTAdBgNVHQ4EFgQUJoSwCjjFC5CV1wxN0JPMeIMGeDAwHwYDVR0jBBgw
FoAUJoSwCjjFC5CV1wxN0JPMeIMGeDAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAANBALT0VU3k6GZ4LoYk8lFMvTOngqOMw0P3cIjotylvCMfiSi+cPJUb
sN/VD/VaFh4z7E44BFKP/A42Y+BBjjj4X6A=
-----END CERTIFICATE-----
Some human-readable description of cert 2
-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJALRiMLAh2wL9MA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRl
c3QyMB4XDTI1MDEwMTAwMDAwMFoXDTI2MDEwMTAwMDAwMFowETEPMA0GA1UEAwwG
dGVzdDIwXDANBgkqhkiG9w0BAQEFAANLADBIAkEA0Z3VS5JJcds3xf0gSfLEtEjn
Muqy+97YHUBzBKAFMnb8NSOqCjrfBfRkzgEiXsAy+D/UCHfaAT6JxVwrZJwG7wID
AQABo1MwUTAdBgNVHQ4EFgQUJoSwCjjFC5CV1wxN0JPMeIMGeDAwHwYDVR0jBBgw
FoAUJoSwCjjFC5CV1wxN0JPMeIMGeDAwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG
9w0BAQsFAANBALT0VU3k6GZ4LoYk8lFMvTOngqOMw0P3cIjotylvCMfiSi+cPJUb
sN/VD/VaFh4z7E44BFKP/A42Y+BBjjj4X6A=
-----END CERTIFICATE-----
Trailing text after last cert
`)

	blocks, err := readPEMBlocks(bytes.NewReader(pemData))
	require.NoError(t, err)
	require.Len(t, blocks, 2, "should parse both PEM blocks despite interleaved text")
	assert.Equal(t, "CERTIFICATE", blocks[0].Type)
	assert.Equal(t, "CERTIFICATE", blocks[1].Type)
}

func TestReadPKCS12BlocksRSA(t *testing.T) {
	// Generate RSA key and self-signed cert
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	password := "test-password"
	pfxData, err := pkcs12.Modern2023.Encode(rsaKey, cert, nil, password)
	require.NoError(t, err)

	blocks, err := readPKCS12Blocks(bytes.NewReader(pfxData), password)
	require.NoError(t, err)

	require.Len(t, blocks, 2, "should have 1 key + 1 cert")
	var keyCount, certCount int
	for _, block := range blocks {
		switch block.Type {
		case "PRIVATE KEY":
			keyCount++
			// Verify the key round-trips correctly
			recovered, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			require.NoError(t, err)
			recoveredRSA, ok := recovered.(*rsa.PrivateKey)
			require.True(t, ok)
			assert.Equal(t, rsaKey.D.Bytes(), recoveredRSA.D.Bytes())
		case "CERTIFICATE":
			certCount++
		}
	}
	assert.Equal(t, 1, keyCount, "should have 1 private key")
	assert.Equal(t, 1, certCount, "should have 1 certificate")
}

func TestReadPEMBlocksIOError(t *testing.T) {
	_, err := readPEMBlocks(&errReader{errors.New("disk failure")})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading PEM data")
}
