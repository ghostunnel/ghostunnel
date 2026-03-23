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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

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
