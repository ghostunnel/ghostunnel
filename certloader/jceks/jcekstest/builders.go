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

// Package jcekstest provides test helpers for building JCEKS keystore binaries.
package jcekstest

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"slices"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/certloader/jceks"
	"github.com/stretchr/testify/require"
)

// JCEKS format constants (from the JCEKS specification).
const (
	jceksMagic          uint32 = 0xcececece
	jceksVersion        uint32 = 0x02
	privateKeyEntryTag  uint32 = 1
	trustedCertEntryTag uint32 = 2

	pbeSaltLen     = 8
	pbeHalfSaltLen = pbeSaltLen / 2
	pbeKeyLen      = 24
)

// oidPBEWithMD5AndDES3CBC is the algorithm identifier used by JCEKS for private key encryption.
var oidPBEWithMD5AndDES3CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}

// pbeParameters is the ASN.1 structure stored in encryptedPrivateKeyInfo.
type pbeParameters struct {
	Salt       []byte
	Iterations int
}

// encryptedPrivateKeyInfo mirrors the JCEKS encrypted-private-key envelope.
type encryptedPrivateKeyInfo struct {
	Algo         pkix.AlgorithmIdentifier
	EncryptedKey []byte
}

// BuildMinimalJCEKS constructs a minimal JCEKS binary containing one trusted certificate entry.
func BuildMinimalJCEKS(t *testing.T, alias string, certDER []byte, password string) []byte {
	t.Helper()

	encodedPassword, err := jceks.EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer

	// Header: magic + version
	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksMagic))
	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksVersion))

	// Entry count: 1
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))

	// Trusted cert entry tag
	require.NoError(t, binary.Write(&body, binary.BigEndian, trustedCertEntryTag))

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

	// Compute and append integrity hash
	h := jceks.MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

// derivePBEParams reproduces the PBEWithMD5AndDES3CBC key derivation used by JCEKS.
func derivePBEParams(password []byte, salt []byte, iterations uint) (key []byte, iv []byte) {
	initState := slices.Clone(salt)
	if subtle.ConstantTimeCompare(initState[:pbeHalfSaltLen], initState[pbeHalfSaltLen:]) == 1 {
		slices.Reverse(initState[:pbeHalfSaltLen])
	}

	hashChain := func(state []byte) []byte {
		h := md5.New()
		for i := uint(0); i < iterations; i++ {
			h.Write(state)
			h.Write(password)
			state = h.Sum(state[:0])
			h.Reset()
		}
		return state
	}
	state := append(hashChain(initState[:pbeHalfSaltLen]), hashChain(initState[pbeHalfSaltLen:])...)
	return state[:pbeKeyLen], state[pbeKeyLen:]
}

// pkcs5Pad applies PKCS#5 padding to plaintext for the given block size.
func pkcs5Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// EncryptPBEWithMD5AndDES3CBC encrypts a PKCS#8 private key using the JCEKS PBE scheme
// and returns the ASN.1-encoded encryptedPrivateKeyInfo. This is the exact format the
// JCEKS parser expects in private-key entries.
func EncryptPBEWithMD5AndDES3CBC(t *testing.T, pkcs8DER []byte, password string) []byte {
	t.Helper()

	salt := make([]byte, pbeSaltLen)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	// Ensure the two halves are different (otherwise derivePBEParams reverses one).
	salt[0] ^= 0xFF

	iterations := uint(200000)
	desKey, cbcIV := derivePBEParams([]byte(password), salt, iterations)

	blk, err := des.NewTripleDESCipher(desKey)
	require.NoError(t, err)
	enc := cipher.NewCBCEncrypter(blk, cbcIV)

	padded := pkcs5Pad(pkcs8DER, enc.BlockSize())
	ciphertext := make([]byte, len(padded))
	enc.CryptBlocks(ciphertext, padded)

	params := pbeParameters{
		Salt:       salt,
		Iterations: int(iterations),
	}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: ciphertext,
	}

	result, err := asn1.Marshal(epki)
	require.NoError(t, err)
	return result
}

// PrivateKeyEntry describes a single private-key entry in a JCEKS binary.
type PrivateKeyEntry struct {
	Alias           string
	EncryptedKeyDER []byte
	CertDER         []byte
}

// BuildJCEKSWithMultiplePrivateKeys constructs a JCEKS binary with several private-key entries.
// Each entry is emitted in the order supplied. This is useful for verifying iteration behavior
// in callers that loop over ListPrivateKeys.
func BuildJCEKSWithMultiplePrivateKeys(t *testing.T, entries []PrivateKeyEntry, password string) []byte {
	t.Helper()

	encodedPassword, err := jceks.EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer

	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksMagic))
	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksVersion))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(entries))))

	for _, entry := range entries {
		require.NoError(t, binary.Write(&body, binary.BigEndian, privateKeyEntryTag))

		require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(entry.Alias))))
		_, err = body.WriteString(entry.Alias)
		require.NoError(t, err)

		require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(len(entry.EncryptedKeyDER))))
		_, err = body.Write(entry.EncryptedKeyDER)
		require.NoError(t, err)

		// Always emit exactly one certificate per entry.
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(1)))

		certType := "X.509"
		require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(certType))))
		_, err = body.WriteString(certType)
		require.NoError(t, err)
		require.NoError(t, binary.Write(&body, binary.BigEndian, int32(len(entry.CertDER))))
		_, err = body.Write(entry.CertDER)
		require.NoError(t, err)
	}

	h := jceks.MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

// BuildJCEKSWithPrivateKey constructs a JCEKS binary containing one private key entry.
func BuildJCEKSWithPrivateKey(t *testing.T, alias string, encryptedKeyDER []byte, certDER []byte, password string) []byte {
	t.Helper()

	encodedPassword, err := jceks.EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer

	// Header
	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksMagic))
	require.NoError(t, binary.Write(&body, binary.BigEndian, jceksVersion))

	// Entry count: 1
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))

	// Private key entry tag
	require.NoError(t, binary.Write(&body, binary.BigEndian, privateKeyEntryTag))

	// Alias
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err = body.WriteString(alias)
	require.NoError(t, err)

	// Timestamp
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

	// Encrypted key bytes (4-byte length prefix, signed int32 per JCEKS spec)
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

	// Compute and append integrity hash
	h := jceks.MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}
