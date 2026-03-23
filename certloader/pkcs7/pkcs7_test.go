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

package pkcs7

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"crypto/ed25519"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractCertificates(t *testing.T) {
	// Generate a self-signed certificate
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "pkcs7-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	// Build a minimal PKCS#7 SignedData structure
	signedData := struct {
		Version          int
		DigestAlgorithms asn1.RawValue `asn1:"set"`
		ContentInfo      asn1.RawValue
		Certificates     []asn1.RawValue `asn1:"tag:0,optional,set"`
		SignerInfos      asn1.RawValue   `asn1:"set"`
	}{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{Tag: 17, Class: asn1.ClassUniversal, IsCompound: true, Bytes: []byte{}},
		ContentInfo:      asn1.RawValue{FullBytes: mustMarshal(t, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})},
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

	// Extract certificates
	certs, err := ExtractCertificates(p7Data)
	assert.NoError(t, err)
	require.Len(t, certs, 1)
	assert.Equal(t, "pkcs7-test", certs[0].Subject.CommonName)
}

func TestParseSignedDataInvalid(t *testing.T) {
	_, err := ParseSignedData([]byte{0x00, 0x01, 0x02})
	assert.Error(t, err)
}

func TestExtractCertificatesInvalid(t *testing.T) {
	_, err := ExtractCertificates([]byte{0x00, 0x01, 0x02})
	assert.Error(t, err)
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := asn1.Marshal(v)
	require.NoError(t, err)
	return data
}
