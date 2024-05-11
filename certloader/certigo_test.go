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
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
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

	blocks, err := readPEM(cert.Name(), "", "PEM")
	assert.Nil(t, err, "should read PEM file")
	assert.Len(t, blocks, 1, "should find one PEM block")
}

func TestReadPEMInvalid(t *testing.T) {
	cert, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cert.Name())

	_, err = cert.Write([]byte("invalid"))
	assert.Nil(t, err, "temp file error")

	blocks, err := readPEM(cert.Name(), "", "PEM")
	assert.NotNil(t, err, "should not parse invalid file")
	assert.Len(t, blocks, 0, "should not return PEM blocks")

	blocks, err = readPEM("does-not-exist", "", "PEM")
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
