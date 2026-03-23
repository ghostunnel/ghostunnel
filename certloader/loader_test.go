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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCertificate = `
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

const testCertificateBad = `
-----BEGIN CERTIFICATE-----
////////////////////////////////////////////////////////////////
-----END CERTIFICATE-----`

func TestReadPEMValid(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte(testCertificate))
	assert.Nil(t, err, "temp file error")

	blocks, err := readCertificateFile(cert.Name(), "", "PEM")
	assert.Nil(t, err, "should read PEM file")
	assert.Len(t, blocks, 1, "should find one PEM block")
}

func TestReadPEMInvalid(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte("invalid"))
	assert.Nil(t, err, "temp file error")

	blocks, err := readCertificateFile(cert.Name(), "", "PEM")
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, blocks, 0, "should not return PEM blocks")

	blocks, err = readCertificateFile("does-not-exist", "", "PEM")
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, blocks, 0, "should not return PEM blocks")
}

func TestReadX509Valid(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte(testCertificate))
	assert.Nil(t, err, "temp file error")

	certs, err := readX509(cert.Name())
	assert.Nil(t, err, "should parse certificate from PEM file")
	assert.Len(t, certs, 1, "should find one certificate")
}

func TestReadX509Invalid(t *testing.T) {
	cert0, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert0.Name())

	cert1, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert1.Name())

	_, err = cert0.Write([]byte("invalid"))
	assert.Nil(t, err, "temp file error")
	_, err = cert1.Write([]byte(testCertificateBad))
	assert.Nil(t, err, "temp file error")

	certs, err := readX509(cert0.Name())
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, certs, 0, "should not parse invalid file")

	certs, err = readX509(cert1.Name())
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, certs, 0, "should not parse invalid file")

	certs, err = readX509("does-not-exist")
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, certs, 0, "should not parse invalid file")
}

func TestReadPEMFormatError(t *testing.T) {
	// File with 1 byte and no known extension → formatForFile fails on Peek
	tmp, err := os.CreateTemp("", "ghostunnel-test-*.tmp")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write([]byte{0x01})
	require.NoError(t, err)
	tmp.Close()

	_, err = readCertificateFile(tmp.Name(), "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to detect format")
}

func TestReadPEMNoCertsFound(t *testing.T) {
	// Empty file with explicit PEM format → 0 blocks → "no certificates found"
	tmp, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	tmp.Close()

	_, err = readCertificateFile(tmp.Name(), "", "PEM")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found")
}

func TestReadX509NoCertificatesInPEM(t *testing.T) {
	// PEM file with only a PRIVATE KEY block → no CERTIFICATE blocks → error
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8,
	})

	tmp, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write(pemData)
	require.NoError(t, err)
	tmp.Close()

	_, err = readX509(tmp.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates found")
}

func TestReadX509ParseCertificateError(t *testing.T) {
	// PEM file with a CERTIFICATE block containing garbage → ParseCertificate fails
	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{0x01, 0x02, 0x03},
	})

	tmp, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write(pemData)
	require.NoError(t, err)
	tmp.Close()

	_, err = readX509(tmp.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "error reading file")
}

func TestReadX509MultipleCerts(t *testing.T) {
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

	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// Write two copies
	pemData := append(block, block...)

	tmp, err := os.CreateTemp("", "ghostunnel-test-*.pem")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())

	_, err = tmp.Write(pemData)
	require.NoError(t, err)
	tmp.Close()

	certs, err := readX509(tmp.Name())
	assert.NoError(t, err)
	assert.Len(t, certs, 2)
}

func TestLoadTrustStoreSystemRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		// System roots are not supported on Windows
		t.SkipNow()
		return
	}

	_, err := LoadTrustStore("")
	assert.Nil(t, err, "should load system trust store if empty string given")
}

func TestLoadTrustStorePEM(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte(testCertificate))
	assert.Nil(t, err, "temp file error")

	_, err = LoadTrustStore(cert.Name())
	assert.Nil(t, err, "should read PEM file trust store")
}

func TestLoadTrustStoreInvalid(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte("this-is-not-a-cert"))
	assert.Nil(t, err, "temp file error")

	_, err = LoadTrustStore("file-that-does-not-exist")
	assert.NotNil(t, err, "should not read non-existent file")

	_, err = LoadTrustStore(cert.Name())
	assert.NotNil(t, err, "should not read non-existent file")
}
