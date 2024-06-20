/*-
 * Copyright 2015 Square Inc.
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

package main

import (
	"crypto/tls"
	"encoding/base64"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCertificate = `
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

var testKeystore, _ = base64.StdEncoding.DecodeString(`
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
CLdyMSoQneGHAgIIAA==`)

var testKeystoreNoPrivKey, _ = base64.StdEncoding.DecodeString(`
MIIEdAIBAzCCBDoGCSqGSIb3DQEHAaCCBCsEggQnMIIEIzCCBB8GCSqGSIb3DQEH
BqCCBBAwggQMAgEAMIIEBQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQYwDgQIMajQ
SoGOIUACAggAgIID2BD884Z9xHNWs//HQneMjFjUhH0J6UwuNgY/tYF3Ol3OoCaq
A9wRPSryJ8/YfAFs3EHpJb+0RYDgT3sJxrHEXwJuVR0hmUzP4rfUhq6z2fvjMYbL
eHWtiEi9aL+lv8Eoczszsqp8KMlbdthskjOIwZiiOBMxTu4Zv7eku0Cwz53U1NCm
wyAFe6n7D/09pvPTURaX0FjmhYdIN+Yb1CnFDC2rHHv3LMRofmYXu6cu0IvY9uvd
Z372R15uIfDr8oyvpQKPhJjEUQ9EfrhLVekWO48LWi4/XoJH6hpnZ8VFHw7M3QIO
CKkITThRhZ5gTTFJi+4/n0q+DzIan9SnniaDeXXgS3zvL7uIm5QWZV7SWIHvnXCA
Mkho6/iDrlu4l0zeLaAiLWg+fuXmnONmX/dGA+AXtK+1wY1dMmrV+kDqBJfuICIb
oXQYxaJ3TgzJnsRXNfXXtX2WSMBfdj+668NdaUcKf/goTrOcznVpGx8Pkm6oHUQ0
r0eK6iV4ApNS9ph7cHS67RQVqbw9PidWYCqYjfasZmcZvLyyVqrSfbUJnjzQARuA
Nblsj0AWGRQIvJHcnrw5Qc3zMtiJh8GhAXCJOKLKlbsjo/aJnn+3KiVwl8BpQhmz
NLbsx8DPdcWUIAxJves8S3UyDaJA6fj4nf1KMNqLu6vpnFptiIiF9pCQcvXTHYc6
tW5nZC5KExxME+Ldkh1Hsp/1DkOsfuFhVAKZrm4F/7Pz5W6BMHteQKeTX3fl1uz0
E/IT5/8yYOan/vYSQNWCcVpc4Z1jcbVkgRtBWqCZ88kq87jvYaFi28znp1qpxGka
q8DDrDQ2ZovXp1KBvLfBzQwRigupi1wQCeKu7pX+TbuTEMkbGPZh0U2dpGm/fxrZ
Nr//yF7N5NLzPWq7qApfZ0Z6DFi+NS5kU6S405ZNHgmwQV+VC324IjuWrEX+AprH
cUSL7wJ34HMsejTaaU4AiqYrN9MdIkn+qsGrQNurzEFJ6NRyAanUwUXyuDN4Yq5m
zgyC07LU5vRRmfdjyBsiJ+QyKLFU6zkQCyCdmENQJr90U596wE9nYDEWABGMSppe
wxQ5fj7+z1alRQZu6jHIal4JH2dJlMAP+MT6Ixokou2GJjuB7qznmpdYTGh2veyj
W7Wvo/eciyujzQ72eO2sRqhzX+SeP+i669ucbYlMBA6DCO101iINxi8LzgOEguWd
KYMB/SV5VsjIOckZuBIn8mMQIAqFGIvqeCS2qovntjHZMyuAbenOFLfi+WRg1KZZ
YAnq2h6R3bmXYwpZzI/S+E/0PQDXHArbsM4XgimleOle+O2bqjAxMCEwCQYFKw4D
AhoFAAQUMdr6fwPsXl5nAlbi51zv2YJHelkECLJyvuiCk4LpAgIIAA==`)

var testKeystoreCertOnly = `
-----BEGIN CERTIFICATE-----
MIIDPjCCAiagAwIBAgIRAPdQja0pEoBqXPO5PCsSDAcwDQYJKoZIhvcNAQELBQAw
NzEVMBMGA1UEChMMY2VydC1tYW5hZ2VyMR4wHAYDVQQDExVmbHVlbnQtYml0LWZv
cndhcmQtY2EwHhcNMTkwMjE0MjMzNDM3WhcNMTkwNTE1MjMzNDM3WjA3MRUwEwYD
VQQKEwxjZXJ0LW1hbmFnZXIxHjAcBgNVBAMTFWZsdWVudC1iaXQtZm9yd2FyZC1j
YTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMHgh2SL8kw77Md/ILpX
0cq8MOvexi3v0uixbUUQMxL8M/3cCcmGIEopoi+GuJuLaa/DOY4c6EHKLgfHCG7M
Uf3YVksf8IXRwHcG6uK9HI7mgsyCPo/rtaYUBGnt8UpGPS8NsLKFWJcGXaclQETp
pBXlqPXHePxmYVJLt8T38IC/fTVx2IwWHTz51HYBuSQK10dvYUGFu53ckE/G7eik
eVRoHIJH9yoqxj1xP9QhFL2GswzoDEs1ketlzZgSdJa1N4bFe7R3Ghqd4spQhM5f
Uf5kmj+lYQLqBErIK3uzOfPHQ0WGoUW/EoW2twuLWZ/7ZDXSKjvMfw7ubS1FvfY2
eIkCAwEAAaNFMEMwDgYDVR0PAQH/BAQDAgKkMA8GA1UdEwEB/wQFMAMBAf8wIAYD
VR0RBBkwF4IVZmx1ZW50LWJpdC1mb3J3YXJkLWNhMA0GCSqGSIb3DQEBCwUAA4IB
AQAyY8/C8yC+5GjKtJmMZfhacIuDw32kzNnsQtLKVNNk3DLA/9yLQx3FIjOV+ON4
1zwhsQ/ZatTuWbxYqzymXE6Ti1Q+yiCjvGsz9fmQ60OwkMxxAcrAY4hd0IipPhNB
ygCDcUf65hPgOvSn+NQJY92XZAGZz9Uwppl+l/1Dda+o+v8jAXJwQo3qkLmRYHuc
uyupqf08h2KgLtfDp6XW+m/kPgjA+S7H2jXcKZk1mZqsSJ5WO1GtGUlfJyfPR8m2
6iPYjqdyz7KL/m+LjngudVruTqVmoT7mI5C+7jsS/K0+rLPhv6d2vD/zcvbjONn7
F9hYbnHTh38g/4uq2fVnW6C0
-----END CERTIFICATE-----`

var testKeystoreKeyPath = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAweCHZIvyTDvsx38gulfRyrww697GLe/S6LFtRRAzEvwz/dwJ
yYYgSimiL4a4m4tpr8M5jhzoQcouB8cIbsxR/dhWSx/whdHAdwbq4r0cjuaCzII+
j+u1phQEae3xSkY9Lw2wsoVYlwZdpyVAROmkFeWo9cd4/GZhUku3xPfwgL99NXHY
jBYdPPnUdgG5JArXR29hQYW7ndyQT8bt6KR5VGgcgkf3KirGPXE/1CEUvYazDOgM
SzWR62XNmBJ0lrU3hsV7tHcaGp3iylCEzl9R/mSaP6VhAuoESsgre7M588dDRYah
Rb8Shba3C4tZn/tkNdIqO8x/Du5tLUW99jZ4iQIDAQABAoIBABvfedecvxLyspHj
1wKzSXgKIkZm2rsT9ZB6oakCMTWTiK4Aim+slsvSvHx0s+m421LnkEi8IzACLyfz
F2VGfqsuBQn754p1o2P5XJ+IbKimvztDplbunkjoK9JG4R+6hWVUZIjl3tynj6NO
GbVOmcaEJAxhxyUSWv+H3z20H6GCpfyyWYRbWhzmp1GeoXBb0vsOnPMgOB7pdlYZ
qoUextffEnmuEQ55DKS6G3+UUNlasnfxz/77BGqHuX8pz3p2eK8py1fbAeIth0og
4Ppj+zsB0N/YmifelzDHeQTMNE1RUGVIz195JrsDTvdHJu9R2hPpsstR2cZVPi1F
2WuEwAECgYEA0IJ6sUGesBFtUuWJu26a/iUxZvyTUyz7im6Wr9x0VmVFHUuGhQhP
0QGS3/weM5zOZe5ArIRqTAb67TySL83/SOLRR7s+KL9uS01ZazODOVHaU+ImyWz4
xB3ZI5BCH0dk1BDREkIaMYj6hlJsYvW/aPXeB1wXdO2g5UJXxd2pBAECgYEA7gje
h/+dj52JBbbHygDvuvNbYDhO3MELDIVoFoU5bgQBg3WPGywRikwKtd+7ko9Q5TPW
0LrPvtAk/kZvg6YmtnY9fsGRXM9v5DoRJ1GVB13hYvUsl3bWz+yhYh5FjBiIiQBm
h3QBve7SojmwNgN+untatm+jgxaEBWB33hVzVIkCgYEAzkxqrDpqkXWMnvowfdv/
SfjumiDIewEEl4C3YqRSDrD/4u442CLTJc3Szf4au6InrD5AivAwY6x8VIEbemTs
cebIfZpK8/IDZEnRcPl0mh/cTiZxjdVdhFyr3D38zgnLPu6sjM4OMHiAtqmSR48x
pN2uocWCB9Sc3nf3c/POKAECgYAozmZvxBdbvnL2As6fR6fRUdTRWvXSDFn7jIc6
jR46SP+FbMraqqRbJAwV/8PlLSJ+GHP0FoJ0wLQGz0ZguEQctYp3R3HHClyxMG8u
YWL9/08bKtK5KItM29ESxAPCL5aAfgwVnoKJ7/42B1O4/sJj76+uZNcQKvT5Av+p
l93MmQKBgH1glvxJzN+B2uaPND/ux4Iz+FVNxwRxOSIvDA87nMlzzCnUQZflJ2Zh
AzsLLA4Co1ouYxA7ecfQe4Y0DjeoZ2Ft5KzAsPhM1D1ztXI5gr3/6HvgJ6xdrXJu
hHV17et3tJKiSuKwz1wSwx7J5hxxPB38+GhfstzSde5LwuAFTfAn
-----END RSA PRIVATE KEY-----`

var testKeystorePassword = "password"

func TestBuildConfig(t *testing.T) {
	tmpKeystore, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystoreNoPrivKey, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystoreSeparateCert, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystoreSeparateKey, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystore.Write(testKeystore)
	tmpKeystoreNoPrivKey.Write(testKeystoreNoPrivKey)

	tmpKeystoreSeparateCert.Write([]byte(testKeystoreCertOnly))
	tmpKeystoreSeparateKey.Write([]byte(testKeystoreKeyPath))

	tmpKeystoreSeparateCert.Sync()
	tmpKeystoreSeparateKey.Sync()

	tmpKeystore.Sync()

	defer os.Remove(tmpKeystore.Name())
	defer os.Remove(tmpKeystoreNoPrivKey.Name())
	defer os.Remove(tmpKeystoreSeparateCert.Name())
	defer os.Remove(tmpKeystoreSeparateKey.Name())

	_, err = buildConfig("")
	assert.NotNil(t, err, "should fail to build config with no cipher suites")

	conf, err := buildConfig("AES,CHACHA")
	assert.Nil(t, err, "should be able to build TLS config")
	assert.True(t, conf.MinVersion == tls.VersionTLS12, "must have correct TLS min version")

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	cert, err := buildCertificate("", "", "", "", tmpKeystoreSeparateCert.Name(), logger)
	assert.NotNil(t, cert, "cert with empty keystorePath should not be nil")
	assert.Nil(t, err, "empty keystorePath should not raise an error")

	cert, err = buildCertificate(tmpKeystore.Name(), "", "", "totes invalid", tmpKeystoreSeparateCert.Name(), logger)
	assert.Nil(t, cert, "cert with invalid params should be nil")
	assert.NotNil(t, err, "should reject invalid keystore pass")

	cert, err = buildCertificate("does-not-exist", "", "", testKeystorePassword, tmpKeystoreSeparateCert.Name(), logger)
	assert.Nil(t, cert, "cert with invalid params should be nil")
	assert.NotNil(t, err, "should reject missing keystore (not found)")

	cert, err = buildCertificate(tmpKeystoreNoPrivKey.Name(), "", "", "", tmpKeystoreSeparateCert.Name(), logger)
	assert.Nil(t, cert, "cert with invalid params should be nil")
	assert.NotNil(t, err, "should reject invalid keystore (no private key)")

	cert, err = buildCertificate("/dev/null", "", "", "", tmpKeystoreSeparateCert.Name(), logger)
	assert.Nil(t, cert, "cert with invalid params should be nil")
	assert.NotNil(t, err, "should reject invalid keystore (empty)")

	cert, err = buildCertificate("", tmpKeystoreSeparateCert.Name(), tmpKeystoreSeparateKey.Name(), "", tmpKeystoreSeparateCert.Name(), logger)
	assert.NotNil(t, cert, "cert with separate key should not be nil")
	assert.Nil(t, err, "cert with separate key should be ok")
}

func TestCipherSuitePreference(t *testing.T) {
	conf, err := buildConfig("XYZ")
	assert.NotNil(t, err, "should not be able to build TLS config with invalid cipher suite option")

	_, err = buildServerConfig("XYZ")
	assert.NotNil(t, err, "should not be able to build TLS config with invalid cipher suite option")

	conf, err = buildConfig("")
	assert.NotNil(t, err, "should not be able to build TLS config wihout cipher suite selection")

	conf, err = buildConfig("CHACHA,AES")
	assert.Nil(t, err, "should be able to build TLS config")
	assert.True(t, conf.CipherSuites[0] == tls.TLS_CHACHA20_POLY1305_SHA256, "expecting TLS 1.3 ChaCha20")

	conf, err = buildConfig("AES,CHACHA")
	assert.Nil(t, err, "should be able to build TLS config")
	assert.True(t, conf.CipherSuites[0] == tls.TLS_AES_128_GCM_SHA256, "expecting TLS 1.3 AES")

	conf, err = buildConfig("AES,CHACHA,UNSAFE-AZURE")
	assert.NotNil(t, err, "should not be able to build TLS config with unsafe cipher suite without flag")

	*allowUnsafeCipherSuites = true
	conf, err = buildConfig("UNSAFE-AZURE")
	assert.Nil(t, err, "should be able to build TLS config")
	assert.True(t, conf.CipherSuites[0] == tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "expecting AES")
	*allowUnsafeCipherSuites = false
}

func TestReload(t *testing.T) {
	tmpKeystore, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpCaBundle, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpCaBundle.WriteString(testCertificate)
	tmpCaBundle.WriteString("\n")
	tmpCaBundle.Sync()
	tmpKeystore.Write(testKeystore)
	tmpKeystore.Sync()

	defer os.Remove(tmpCaBundle.Name())
	defer os.Remove(tmpKeystore.Name())

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	c, err := buildCertificate(tmpKeystore.Name(), "", "", testKeystorePassword, tmpCaBundle.Name(), logger)
	assert.Nil(t, err, "should be able to build certificate")

	c.Reload()
}

func TestBuildConfigSystemRoots(t *testing.T) {
	if runtime.GOOS == "windows" {
		// System roots are not supported on Windows
		t.SkipNow()
		return
	}

	tmpKeystore, err := os.CreateTemp("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystore.Write(testKeystore)
	tmpKeystore.Sync()

	defer os.Remove(tmpKeystore.Name())

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	c, err := buildCertificate(tmpKeystore.Name(), "", "", testKeystorePassword, "", logger)
	assert.Nil(t, err, "should be able to build certificate")

	c.Reload()
}
