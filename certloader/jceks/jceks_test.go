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

package jceks

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"crypto/ed25519"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMinimalJCEKS constructs a minimal JCEKS binary containing one trusted certificate entry.
func buildMinimalJCEKS(t *testing.T, alias string, certDER []byte, password string) []byte {
	t.Helper()

	// Encode integrity password
	encodedPassword, err := encodeIntegrityPassword(password)
	require.NoError(t, err)

	// Build the body (everything that gets hashed)
	var body bytes.Buffer

	// Header: magic + version
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))

	// Entry count: 1
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))

	// Trusted cert entry tag
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(trustedCertEntryTag)))

	// Alias (modified UTF-8 string with 2-byte length prefix)
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err = body.WriteString(alias)
	require.NoError(t, err)

	// Timestamp (millis since epoch)
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

	// Certificate type string: "X.509"
	certType := "X.509"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(certType))))
	_, err = body.WriteString(certType)
	require.NoError(t, err)

	// Certificate DER bytes (4-byte length prefix)
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(certDER))))
	_, err = body.Write(certDER)
	require.NoError(t, err)

	// Compute integrity hash
	h := sha1.New()
	h.Write(encodedPassword)
	h.Write([]byte(jceksIntegrityMagic))
	h.Write(body.Bytes())
	digest := h.Sum(nil)

	// Append digest
	body.Write(digest)

	return body.Bytes()
}

func TestLoadFromReaderTrustedCert(t *testing.T) {
	// Generate a self-signed certificate
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jceks-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	jceksData := buildMinimalJCEKS(t, "myalias", certDER, password)

	// Parse the JCEKS data
	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	// Verify we can list and retrieve the certificate
	aliases := ks.ListCerts()
	require.Len(t, aliases, 1)
	assert.Equal(t, "myalias", aliases[0])

	cert, err := ks.GetCert("myalias")
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Equal(t, "jceks-test", cert.Subject.CommonName)

	// Verify no private keys
	assert.Empty(t, ks.ListPrivateKeys())
}

func TestLoadFromReaderInvalidMagic(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
	_, err := LoadFromReader(bytes.NewReader(data), []byte("password"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestLoadFromReaderBadPassword(t *testing.T) {
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

	jceksData := buildMinimalJCEKS(t, "alias", certDER, "correct-password")

	_, err = LoadFromReader(bytes.NewReader(jceksData), []byte("wrong-password"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrIntegrityProtectionViolation)
}

func TestKeyStoreString(t *testing.T) {
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
	jceksData := buildMinimalJCEKS(t, "myalias", certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	str := ks.String()
	assert.Contains(t, str, "myalias")
	assert.Contains(t, str, "trusted-cert")
}
