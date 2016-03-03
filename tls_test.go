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
	"io/ioutil"
	"os"
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

var testPrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEArgRtl/cQxv9yJbmcaU3Kt/k9x/PdmeNZHLWS8GuK48Po1BJl
pNZM+Ymdt1L9DkUfSn/pmN1kpd/p/tY2cDMnBbRcrs1Pc3YOtZ+BCqutW8sBiV+q
AecLsXGqrsUKmBaN/svzBxBd90hiSF2wTieiwuYJG/HupL7C5qxvqcvMG2Dtv31m
87wr+x7OsMiPDN6YFYDVWi/O3D+8YPgnj+EPSGI46oUZay3AXEH2gbh39AnjlW20
swa6JkJj4DgjIGA8LGmGsR5zrN/wfi79x5BsHyLUgyYPVVOyr1p95WEwq6hKfYGz
dVEHpz0WkvjX9+03mZilkK15kf6pD8OEr/IPPQIDAQABAoIBAGE8QDDF8S4A1ruV
t3xv53JdZtQvxAeVLdoI645DyVvzwEmf7gPpayGUb/hb+uLaZN2wE8tDClZVg97N
u6V+L7PUUGWse1S9BwMdmXFo9HlyOe2U8t4VSEdiiEkX+Q96quVQ+P9deeQPIjvl
ffpt01isSTLAQOT1YtqaR9rM8cPpvIVix29v/GfBlJSVY7FDjTPHkfv2PiXncxk4
JKTF2Nc01OSNmRBCN+7TrQOvOSJYr1fwvs7v1xI2ABKQiTK4SbFAf+cpriEkuZsL
xtlb7KuahG/cb0eeXEVqCEtqeBaCkXqVYUQwQa7u+pFWJbzPf34tSgxMPrQd9Pkr
ojaE0lECgYEA58/az9tz0ZJt+8zSMnTNkunlcfsR2wKANP19emniDN+PS4CwHPbf
OxQFIazR2F9kbHtVoRxP6W9HVNRsc+Ta/8D8ZeYs8u7sImwqmMEmlc88YY+6WI7/
0CRkZN20aZsqgwDsrNcXUq0ifNzulxHjxodDiqheNsZ1Y1SDbrfnk+sCgYEAwCzE
TsR0Ol2FCBazgCTrs1PlZL64br8Pd7mGtx/wUVA0dg7oROvMC2mn7iR7RKmT67Pj
oH7tW1cd1B/XPB1WkChbI9CqKR1XeS0+St8wqrinnb7RB4f1gtPYKmKBxjDTZs+c
of8pebOMieHE2y1OOmuj7kuscK35kEladYfqp3cCgYAk1BUDaO4hoY3vrz7F3WC7
soVNcoIHtYIA6TUCOcg8G1h8ullAgMg+bpPSIc7E/YLK6V1VV1Yq1A8VHxqL3xQc
BeETn1oMzoCdh2nNEwK6Uk5ZgagtYaqqut1oWQDMtmYuofr4CsQd0nvkMoWFYsY5
SEwmv1EYircjrM2kzXrxOQKBgGnb/yM4mqHQBEkJYEW1kNTO4S0W1jfDLX0RCMF1
aYcRPGTQH2hfz511zRikpfaTxzTuefReFtfa7EZ+Z6zoqFdus43OEv3k+Nt6bbcG
rSNN5p9BjpmsbjRsB8aJTt1i5gDbWnfuO+WbX05QvITTtyT9SGcq7kl/vFqb3aWi
gkNPAoGBALtEwTNfsd2vHGn4yS27v1i1eRrVQxiGR/9+/yObTmwBCSHjI6T7H5H7
pEB0ktBcO+jH0KujblvBJrOTEs599XdFKsX+SOIYxH1plV9qMMd9VBuV66nB7rEO
u1wsPBxUVfrnDxA8gyM2ghew9xRJNujJVQAgx/vyygr1u2N2LHPL
-----END RSA PRIVATE KEY-----`

var testKeystore, _ = base64.StdEncoding.DecodeString(`
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
CLdyMSoQneGHAgIIAA==`)

var testKeystoreNoPrivKey, _ = base64.StdEncoding.DecodeString(`
aS2WupjMK5N7BPXzzjDbsu6bGFP1m+rxTF+ViGYbZY753I9o0dTULBo1rubCpQzT
6Gwhy2gs9PrS0RmV7ohhuFL15c+bbOlqsmxYvvkNYRKiZenp04M4kZUPr8qkA/IK
Yjzb9I2xQxlJ3BRxNCYO8asodaSyC9JP4DdZ2pCrY8F7WiZpBzy0XEODgQrTAdfe
infTN3eJzyV8igXOlo1Axmo4AX30m5PZa5U6ZpIF+Rl2NeYL9lU/vJlngKf66vZO
SSadFQ/08oXZjYNp98wCxvprmcoQ29Spae9qPruXu1PcysopFknZstJ+PiOcutkY
Bi8roRGs3+oIcKvQwEUZM8O6FtsABnLVQaJQaB88Q54Tp17NQDUb7D2aGY0YJIi6
a9BlkeNGbz3xoYPcIj2ygM2+e7r5YbRVylP79aO162S0worYYSP282u2kQgdL0yd
1CXlkx66VxTjgPE2sV+3fHWJcGiyVOf9LepWZu9qFkxtvlCrab/fHJQHwRWkuJ93
iZokDPLDwNYhFqa01iFFUlO9A/GJ+ptRSesE8MmKO9bOgU1X+qtF4MC4+z1cEkMc
JTYoNh2CjNgEpcx8CGFjsxyQMpvVfSah1n30kMrZmH+0peVdS0ojLJLvaT37PX1y
u0KsewRI2yB5MNPzX+rZr5BK4UOCrvM+AKvzV6mH3IZ9uBw6GuNikdrA8Ql1JirU
K+/0HuqdHfog04Y3qR5G/xD3qjau69wJEaqb30Q8qVtxX6hhCj+6rmj+cR3UvRxQ
3nuy6SLKn5wVDl/I51sbGiNXcq6Dk7Nzgd96QfuYCWA/UOATl8xruYiNMX85C98o
jI1sB28WlKGTMmZsb7XbJ+5So1TyxGyF1GiUPFk19fwaV2+b36oIzW+ixgZNUOy1
WR18HLB3BUKWdB0FT1RjaJBT+DFcgkmOdYL+kyfCeikf6KhmDStp75mIula1RDPd
Jk0AZRSAWAk0Qh4GdHLfvH11Apo5v0/LxHvct4F1AXope8KShmA0zoTkIrgmley7
eN2k0O4s/HQzHRlyNmYyTrxABp9CwTEcBYTfRYMDEwITAJBgUrDgMCGgUABBQPT6
fJErWb+LYoXcZt/VyFB4otEAQI/BZn7NX+OiQCAggA`)

var testKeystorePassword = "password"

func init() {
	if testKeystore == nil {
		panic("invalid test keystore data")
	}
}

func TestParseKeystore(t *testing.T) {
	certs, key, err := parseKeystore(testKeystore, testKeystorePassword)
	assert.NotNil(t, certs, "must parse certs")
	assert.NotNil(t, key, "must parse private key")
	assert.Nil(t, err, "must parse keystore")

	certs, key, err = parseKeystore([]byte{0x00}, "invalid")
	assert.Nil(t, certs, "must not parse certs from invalid keystore")
	assert.Nil(t, key, "must not parse private key from invalid keystore")
	assert.NotNil(t, err, "must not parse invalid keystore")

	_, key, err = parseKeystore(testKeystoreNoPrivKey, "")
	assert.Nil(t, key, "no private key in keystore, should be nil")
	assert.NotNil(t, err, "must not parse invalid keystore")
}

func TestBuildConfig(t *testing.T) {
	tmpKeystore, err := ioutil.TempFile("", "ghostunnel-test")
	panicOnError(err)

	tmpCaBundle, err := ioutil.TempFile("", "ghostunnel-test")
	panicOnError(err)

	tmpKeystore.Write(testKeystore)
	tmpCaBundle.WriteString(testCertificate)
	tmpCaBundle.WriteString("\n")

	tmpKeystore.Sync()
	tmpCaBundle.Sync()

	defer os.Remove(tmpKeystore.Name())
	defer os.Remove(tmpCaBundle.Name())

	conf, err := buildConfig(tmpKeystore.Name(), testKeystorePassword, tmpCaBundle.Name())
	assert.Nil(t, err, "should be able to build TLS config")
	assert.NotNil(t, conf.Certificates, "config must have certs")
	assert.NotNil(t, conf.RootCAs, "config must have CA certs")
	assert.NotNil(t, conf.ClientCAs, "config must have CA certs")
	assert.True(t, conf.MinVersion == tls.VersionTLS12, "must have correct TLS min version")

	_, err = buildConfig(tmpKeystore.Name(), testKeystorePassword, "does-not-exist")
	assert.NotNil(t, err, "should reject invalid CA cert bundle")

	_, err = buildConfig("does-not-exist", testKeystorePassword, tmpCaBundle.Name())
	assert.NotNil(t, err, "should reject missing keystore (not found)")
}
