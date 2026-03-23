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
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildMinimalJCEKS constructs a minimal JCEKS binary containing one trusted certificate entry.
func buildMinimalJCEKS(t *testing.T, alias string, certDER []byte, password string) []byte {
	t.Helper()

	// Encode integrity password
	encodedPassword, err := EncodeIntegrityPassword(password)
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
	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

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

// pkcs5Pad applies PKCS#5 padding to plaintext for the given block size.
func pkcs5Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

// encryptPBEWithMD5AndDES3CBC encrypts a PKCS#8 private key using the JCEKS PBE scheme
// and returns the ASN.1-encoded encryptedPrivateKeyInfo.
func encryptPBEWithMD5AndDES3CBC(t *testing.T, pkcs8DER []byte, password string) []byte {
	t.Helper()

	salt := make([]byte, pbeMD5DES3CBCSaltLen)
	_, err := rand.Read(salt)
	require.NoError(t, err)
	// Ensure the two halves are different (otherwise derivePBEWithMD5AndDES3CBCParams reverses one)
	salt[0] ^= 0xFF

	iterations := uint(200000)
	desKey, cbcIV := derivePBEWithMD5AndDES3CBCParams([]byte(password), salt, iterations)

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

// buildJCEKSWithPrivateKey constructs a JCEKS binary containing one private key entry.
func buildJCEKSWithPrivateKey(t *testing.T, alias string, encryptedKeyDER []byte, certDER []byte, password string) []byte {
	t.Helper()

	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer

	// Header
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))

	// Entry count: 1
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))

	// Private key entry tag
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))

	// Alias
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err = body.WriteString(alias)
	require.NoError(t, err)

	// Timestamp
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

	// Encrypted key bytes (4-byte length prefix)
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
	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

// generateSelfSignedCert creates a self-signed cert and returns (certDER, privateKey).
func generateRSACert(t *testing.T) ([]byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER, key
}

func generateECDSACert(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return certDER, key
}

func generateED25519Cert(t *testing.T) ([]byte, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ed25519-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)
	return certDER, priv
}

func TestRecoverRSAKey(t *testing.T) {
	certDER, key := generateRSACert(t)
	password := "changeit"

	// Marshal RSA key as PKCS#1 inside a PKCS#8 privateKeyInfo
	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pki := privateKeyInfo{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: oidPublicKeyRSA,
		},
		PrivateKey: pkcs1DER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "mykey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	aliases := ks.ListPrivateKeys()
	require.Len(t, aliases, 1)
	assert.Equal(t, "mykey", aliases[0])

	recovered, certs, err := ks.GetPrivateKeyAndCerts("mykey", []byte(password))
	require.NoError(t, err)
	require.Len(t, certs, 1)

	rsaKey, ok := recovered.(*rsa.PrivateKey)
	require.True(t, ok, "expected *rsa.PrivateKey, got %T", recovered)
	assert.Equal(t, key.D.Bytes(), rsaKey.D.Bytes())
}

func TestRecoverECDSAKey(t *testing.T) {
	certDER, key := generateECDSACert(t)
	password := "changeit"

	// Marshal ECDSA key: the JCEKS Recover path expects the private key bytes
	// to be an ecPrivateKey without the curve OID (it gets the OID from the algorithm parameters).
	ecDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	// Parse back to strip the named curve OID (which Recover re-adds from algo params)
	var ecKey ecPrivateKey
	_, err = asn1.Unmarshal(ecDER, &ecKey)
	require.NoError(t, err)
	ecKey.NamedCurveOID = nil
	strippedDER, err := asn1.Marshal(ecKey)
	require.NoError(t, err)

	// Marshal the curve OID as algorithm parameters
	curveOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7} // P-256
	curveOIDBytes, err := asn1.Marshal(curveOID)
	require.NoError(t, err)

	pki := privateKeyInfo{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyEC,
			Parameters: asn1.RawValue{FullBytes: curveOIDBytes},
		},
		PrivateKey: strippedDER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "eckey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	recovered, certs, err := ks.GetPrivateKeyAndCerts("eckey", []byte(password))
	require.NoError(t, err)
	require.Len(t, certs, 1)

	ecRecovered, ok := recovered.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey, got %T", recovered)
	assert.Equal(t, key.D.Bytes(), ecRecovered.D.Bytes())
}

func TestRecoverED25519Key(t *testing.T) {
	certDER, key := generateED25519Cert(t)
	password := "changeit"

	// Marshal ED25519 key as PKCS#8
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "edkey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	recovered, certs, err := ks.GetPrivateKeyAndCerts("edkey", []byte(password))
	require.NoError(t, err)
	require.Len(t, certs, 1)

	edKey, ok := recovered.(ed25519.PrivateKey)
	require.True(t, ok, "expected ed25519.PrivateKey, got %T", recovered)
	assert.Equal(t, key.Seed(), edKey.Seed())
}

func TestRecoverWrongPassword(t *testing.T) {
	certDER, key := generateRSACert(t)
	password := "changeit"

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pki := privateKeyInfo{
		Version: 0,
		Algo:    pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1DER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	// Encrypt with the correct password
	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	// Build JCEKS with the correct password for integrity
	jceksData := buildJCEKSWithPrivateKey(t, "mykey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	// Try to recover with a different password
	_, _, err = ks.GetPrivateKeyAndCerts("mykey", []byte("wrong-password"))
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

func TestRecoverUnsupportedAlgorithm(t *testing.T) {
	certDER, _ := generateRSACert(t)
	password := "changeit"

	// Build a fake encryptedPrivateKeyInfo with a non-PBE OID
	fakeOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5}
	params := pbeParameters{Salt: make([]byte, 8), Iterations: 1}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  fakeOID,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: []byte("fake-encrypted-data-1234567890ab"),
	}
	encryptedKey, err := asn1.Marshal(epki)
	require.NoError(t, err)

	jceksData := buildJCEKSWithPrivateKey(t, "mykey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	_, _, err = ks.GetPrivateKeyAndCerts("mykey", []byte(password))
	assert.ErrorIs(t, err, ErrUnsupportedJCEKSData)
}

func TestGetPrivateKeyAndCertsNonExistent(t *testing.T) {
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
	jceksData := buildMinimalJCEKS(t, "alias", certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	key, certs, err := ks.GetPrivateKeyAndCerts("nonexistent", []byte(password))
	assert.NoError(t, err)
	assert.Nil(t, key)
	assert.Nil(t, certs)
}

func TestPrivateKeyEntryString(t *testing.T) {
	entry := &privateKeyEntry{
		timestamp: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	str := entry.String()
	assert.Contains(t, str, "private-key")
	assert.Contains(t, str, "2025")
}

func TestWithMaxCertificateBytes(t *testing.T) {
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
	jceksData := buildMinimalJCEKS(t, "alias", certDER, password)

	// Set a very small max cert size to trigger an error
	ks := new(KeyStore)
	err = ks.ParseWithOptions(bytes.NewReader(jceksData), []byte(password), WithMaxCertificateBytes(10))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestWithMaxPrivateKeyBytes(t *testing.T) {
	certDER, key := generateRSACert(t)
	password := "changeit"

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pki := privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1DER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "mykey", encryptedKey, certDER, password)

	ks := new(KeyStore)
	err = ks.ParseWithOptions(bytes.NewReader(jceksData), []byte(password), WithMaxPrivateKeyBytes(10))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestKeyStoreStringWithPrivateKey(t *testing.T) {
	certDER, key := generateRSACert(t)
	password := "changeit"

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pki := privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1DER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "myrsakey", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	str := ks.String()
	assert.Contains(t, str, "myrsakey")
	assert.Contains(t, str, "private-key")
}

func TestParseHeaderVersionMismatch(t *testing.T) {
	var buf bytes.Buffer
	// Valid JCEKS magic, wrong version
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(0x99)))

	ks := new(KeyStore)
	err := ks.Parse(&buf, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
	assert.Contains(t, err.Error(), "unexpected version")
}

// --- Phase 3: readModifiedUTF8 tests ---

func TestReadModifiedUTF8NulEncoding(t *testing.T) {
	// Java modified UTF-8 encodes NUL as 0xC0 0x80
	input := []byte{0xC0, 0x80}
	result, err := readModifiedUTF8(bytes.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "\x00", result)
}

func TestReadModifiedUTF8TwoByte(t *testing.T) {
	// 'é' (U+00E9) = 0xC3 0xA9 in UTF-8
	input := []byte{0xC3, 0xA9}
	result, err := readModifiedUTF8(bytes.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "é", result)
}

func TestReadModifiedUTF8ThreeByte(t *testing.T) {
	// '世' (U+4E16) = 0xE4 0xB8 0x96 in UTF-8
	input := []byte{0xE4, 0xB8, 0x96}
	result, err := readModifiedUTF8(bytes.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "世", result)
}

func TestReadModifiedUTF8SurrogatePair(t *testing.T) {
	// U+1F600 (😀) is encoded as a UTF-16 surrogate pair: D83D DE00
	// In modified UTF-8, each surrogate is encoded as a 3-byte sequence:
	// D83D → 0xED 0xA0 0xBD
	// DE00 → 0xED 0xB8 0x80
	input := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80}
	result, err := readModifiedUTF8(bytes.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "😀", result)
}

func TestReadModifiedUTF8InvalidFirstByte(t *testing.T) {
	// 0x80 is a continuation byte, invalid as first byte
	input := []byte{0x80}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
	assert.Contains(t, err.Error(), "invalid first rune byte")
}

func TestReadModifiedUTF8BareNul(t *testing.T) {
	// 0x00 is not valid in modified UTF-8 (must use 0xC0 0x80)
	input := []byte{0x00}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
	assert.Contains(t, err.Error(), "1-byte NUL")
}

func TestReadModifiedUTF8UnexpectedEOFTwoByte(t *testing.T) {
	// Truncated 2-byte sequence
	input := []byte{0xC3}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadModifiedUTF8UnexpectedEOFThreeByte(t *testing.T) {
	// Truncated 3-byte sequence
	input := []byte{0xE4, 0xB8}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadModifiedUTF8Invalid2ByteCodepoint(t *testing.T) {
	// Invalid 2-byte sequence: 0xC1 0x80 is an overlong encoding
	input := []byte{0xC1, 0x80}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
}

func TestReadModifiedUTF8MixedContent(t *testing.T) {
	// "Aé世" = 'A' (1-byte) + 'é' (2-byte) + '世' (3-byte)
	input := []byte{0x41, 0xC3, 0xA9, 0xE4, 0xB8, 0x96}
	result, err := readModifiedUTF8(bytes.NewReader(input))
	require.NoError(t, err)
	assert.Equal(t, "Aé世", result)
}

func TestReadModifiedUTF8OutsideBMP(t *testing.T) {
	// A 4-byte UTF-8 start byte (0xF0) is not valid in modified UTF-8
	// (only BMP and surrogate-pair encoding are supported)
	input := []byte{0xF0, 0x9F, 0x98, 0x80}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
	assert.Contains(t, err.Error(), "outside basic multilingual plane")
}

func TestReadModifiedUTF8HighSurrogateNotFollowedByLow(t *testing.T) {
	// High surrogate D83D (0xED 0xA0 0xBD) followed by non-surrogate 3-byte
	// sequence (0xE4 0xB8 0x96 = '世') instead of a low surrogate.
	input := []byte{0xED, 0xA0, 0xBD, 0xE4, 0xB8, 0x96}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
	assert.Contains(t, err.Error(), "invalid modified surrogate")
}

func TestReadModifiedUTF8TwoHighSurrogates(t *testing.T) {
	// Two consecutive high surrogates: D83D D83D
	// D83D → 0xED 0xA0 0xBD
	input := []byte{0xED, 0xA0, 0xBD, 0xED, 0xA0, 0xBD}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, errInvalidModifiedUTF8)
	assert.Contains(t, err.Error(), "invalid supplementary character")
}

func TestReadModifiedUTF8SurrogateUnexpectedEOF(t *testing.T) {
	// High surrogate D83D followed by truncated data (only 2 more bytes)
	input := []byte{0xED, 0xA0, 0xBD, 0xED, 0xB8}
	_, err := readModifiedUTF8(bytes.NewReader(input))
	assert.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

// --- pkcs5Unpad tests ---

func TestPkcs5UnpadValid(t *testing.T) {
	// 8-byte block with 3 bytes of padding
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x03, 0x03, 0x03}
	result, err := pkcs5Unpad(input)
	require.NoError(t, err)
	assert.Equal(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05}, result)
}

func TestPkcs5UnpadTooShort(t *testing.T) {
	_, err := pkcs5Unpad([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

func TestPkcs5UnpadBadPadding(t *testing.T) {
	// Last byte says 3 bytes of padding, but they don't match
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x02, 0x02, 0x03}
	_, err := pkcs5Unpad(input)
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

func TestPkcs5UnpadPadTooLarge(t *testing.T) {
	// Pad byte = 9, larger than block size of 8
	input := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x09}
	_, err := pkcs5Unpad(input)
	assert.ErrorIs(t, err, ErrInvalidCiphertext)
}

// --- validatePasswordPBEWithMD5AndDES3CBC tests ---

func TestValidatePasswordEmpty(t *testing.T) {
	err := validatePasswordPBEWithMD5AndDES3CBC([]byte{})
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestValidatePasswordInvalidChars(t *testing.T) {
	err := validatePasswordPBEWithMD5AndDES3CBC([]byte{0x01})
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

func TestValidatePasswordValid(t *testing.T) {
	err := validatePasswordPBEWithMD5AndDES3CBC([]byte("changeit"))
	assert.NoError(t, err)
}

// --- EncodeIntegrityPassword tests ---

func TestEncodeIntegrityPasswordAboveBMP(t *testing.T) {
	// Emoji U+1F600 is above U+FFFF, should be rejected
	_, err := EncodeIntegrityPassword("\U0001F600")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPassword)
	assert.Contains(t, err.Error(), "unsupported codepoints")
}

func TestEncodeIntegrityPasswordEmpty(t *testing.T) {
	_, err := EncodeIntegrityPassword("")
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPassword)
}

// --- makeParseConfig / ParseWithOptions config error ---

type errOption struct{}

func (e errOption) applyParseOption(*parseConfig) error {
	return errors.New("bad option")
}

func TestParseWithOptionsConfigError(t *testing.T) {
	ks := new(KeyStore)
	err := ks.ParseWithOptions(bytes.NewReader([]byte{}), nil, errOption{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to configure parser")
}

// --- ParseWithOptions entry tag tests ---

func buildJCEKSWithTag(t *testing.T, tag uint32, password string) []byte {
	t.Helper()

	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1))) // 1 entry
	require.NoError(t, binary.Write(&body, binary.BigEndian, tag))
	// Don't need more data — parser will error on the tag before reading further

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

func TestParseWithOptionsSecretKeyEntry(t *testing.T) {
	password := "changeit"
	data := buildJCEKSWithTag(t, secretKeyEntryTag, password)

	_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedJCEKSData)
	assert.Contains(t, err.Error(), "secret key entry")
}

func TestParseWithOptionsUnknownEntryTag(t *testing.T) {
	password := "changeit"
	data := buildJCEKSWithTag(t, 99, password)

	_, err := LoadFromReader(bytes.NewReader(data), []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedJCEKSData)
	assert.Contains(t, err.Error(), "unknown entry tag")
}

// --- GetPrivateKeyAndCerts: no certificates ---

func buildJCEKSWithPrivateKeyNoCerts(t *testing.T, alias string, encryptedKeyDER []byte, password string) []byte {
	t.Helper()

	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))

	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	_, err = body.WriteString(alias)
	require.NoError(t, err)

	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))

	require.NoError(t, binary.Write(&body, binary.BigEndian, int32(len(encryptedKeyDER))))
	_, err = body.Write(encryptedKeyDER)
	require.NoError(t, err)

	// 0 certificates
	require.NoError(t, binary.Write(&body, binary.BigEndian, int32(0)))

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	return body.Bytes()
}

func TestGetPrivateKeyNoCertificates(t *testing.T) {
	certDER, key := generateRSACert(t)
	_ = certDER
	password := "changeit"

	pkcs1DER := x509.MarshalPKCS1PrivateKey(key)
	pki := privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: pkcs1DER,
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKeyNoCerts(t, "nokey", encryptedKey, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	_, _, err = ks.GetPrivateKeyAndCerts("nokey", []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
	assert.Contains(t, err.Error(), "key has no certificates")
}

// --- GetCert: non-existent alias ---

func TestGetCertNonExistentAlias(t *testing.T) {
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
	jceksData := buildMinimalJCEKS(t, "alias", certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	cert, err := ks.GetCert("nonexistent")
	assert.NoError(t, err)
	assert.Nil(t, cert)
}

// --- parseHeader error paths ---

func TestParseHeaderReadMagicError(t *testing.T) {
	_, err := LoadFromReader(bytes.NewReader([]byte{}), []byte("pw"))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestParseHeaderReadVersionError(t *testing.T) {
	// Valid JCEKS magic, but no version bytes
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksMagic)))

	_, err := LoadFromReader(&buf, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

// --- Recover error paths ---

func TestRecoverASN1UnmarshalError(t *testing.T) {
	certDER, _ := generateRSACert(t)
	password := "changeit"

	// protectedKey = invalid ASN.1
	jceksData := buildJCEKSWithPrivateKey(t, "badkey", []byte{0x01, 0x02}, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	_, _, err = ks.GetPrivateKeyAndCerts("badkey", []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
	assert.Contains(t, err.Error(), "failed to parse private key as DER")
}

func TestRecoverUnsupportedKeyAlgorithm(t *testing.T) {
	certDER, _ := generateRSACert(t)
	password := "changeit"

	// Build a privateKeyInfo with a bogus algorithm OID
	pki := privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5}},
		PrivateKey: []byte{0x04, 0x01, 0x02},
	}
	pkcs8DER, err := asn1.Marshal(pki)
	require.NoError(t, err)

	encryptedKey := encryptPBEWithMD5AndDES3CBC(t, pkcs8DER, password)
	jceksData := buildJCEKSWithPrivateKey(t, "unsupported", encryptedKey, certDER, password)

	ks, err := LoadFromReader(bytes.NewReader(jceksData), []byte(password))
	require.NoError(t, err)

	_, _, err = ks.GetPrivateKeyAndCerts("unsupported", []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// --- Truncated entry tests ---

func TestParsePrivateKeyTruncatedAlias(t *testing.T) {
	// JCEKS with private key tag but no alias data
	password := "changeit"
	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))
	// EOF here — no alias

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	_, err = LoadFromReader(&body, []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestParsePrivateKeyTruncatedDate(t *testing.T) {
	password := "changeit"
	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(privateKeyEntryTag)))
	// Alias
	alias := "a"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	body.WriteString(alias)
	// EOF here — no date

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	_, err = LoadFromReader(&body, []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestParseTrustedCertTruncatedDate(t *testing.T) {
	password := "changeit"
	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(trustedCertEntryTag)))
	alias := "a"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	body.WriteString(alias)
	// EOF — no date

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	_, err = LoadFromReader(&body, []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestParseTrustedCertTruncatedCert(t *testing.T) {
	password := "changeit"
	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(trustedCertEntryTag)))
	alias := "a"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	body.WriteString(alias)
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))
	// EOF — no certificate data

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	_, err = LoadFromReader(&body, []byte(password))
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

// --- encoding.go error path tests ---

func TestReadBytesNegativeLength(t *testing.T) {
	// int32(-1) = 0xFFFFFFFF
	buf := bytes.NewReader([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	_, err := readBytes(buf, 1024)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
}

func TestReadBytesReadFullError(t *testing.T) {
	// Length=100 but only 2 data bytes follow
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, int32(100)))
	buf.Write([]byte{0xAA, 0xBB})

	_, err := readBytes(&buf, 1024)
	assert.Error(t, err) // io.ErrUnexpectedEOF
}

func TestReadBytesExceedsMaxLen(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, int32(1000)))

	_, err := readBytes(&buf, 10) // max=10, but length=1000
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrJCEKSDataTooLarge)
}

func TestReadDateError(t *testing.T) {
	_, err := readDate(bytes.NewReader([]byte{0x01}))
	assert.Error(t, err)
}

func TestReadStringError(t *testing.T) {
	_, err := readString(bytes.NewReader([]byte{}))
	assert.Error(t, err)
}

func TestReadCertificateUnsupportedType(t *testing.T) {
	var buf bytes.Buffer
	certType := "PKCS#7"
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint16(len(certType))))
	buf.WriteString(certType)

	_, err := readCertificate(&buf, defaultMaxCertBytes)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedJCEKSData)
	assert.Contains(t, err.Error(), "unable to handle certificate type")
}

func TestReadCertificateParseError(t *testing.T) {
	var buf bytes.Buffer
	certType := "X.509"
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint16(len(certType))))
	buf.WriteString(certType)
	// Garbage DER bytes
	garbage := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	require.NoError(t, binary.Write(&buf, binary.BigEndian, int32(len(garbage))))
	buf.Write(garbage)

	_, err := readCertificate(&buf, defaultMaxCertBytes)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse certificate")
}

// --- pbemd5des3cbc.go error path tests ---

func TestDerivePBEEqualSaltHalves(t *testing.T) {
	// Salt where both halves are identical → triggers reversal of first half
	salt := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xAA, 0xBB, 0xCC, 0xDD}
	key, iv := derivePBEWithMD5AndDES3CBCParams([]byte("password"), salt, 1)
	assert.Len(t, key, 24, "DES3 key should be 24 bytes")
	assert.Len(t, iv, 8, "CBC IV should be 8 bytes")
}

func TestRecoverPBEBadSaltLength(t *testing.T) {
	params := pbeParameters{Salt: make([]byte, 4), Iterations: 1}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: make([]byte, 16),
	}

	_, err = recoverPBEWithMD5AndDES3CBC(epki, []byte("changeit"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected salt length")
}

func TestRecoverPBEBadIterations(t *testing.T) {
	params := pbeParameters{Salt: make([]byte, 8), Iterations: 0}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: make([]byte, 16),
	}

	_, err = recoverPBEWithMD5AndDES3CBC(epki, []byte("changeit"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected iteration count")
}

func TestRecoverPBEExcessiveIterations(t *testing.T) {
	params := pbeParameters{Salt: make([]byte, 8), Iterations: maxPBEIterations + 1}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: make([]byte, 16),
	}

	_, err = recoverPBEWithMD5AndDES3CBC(epki, []byte("changeit"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected iteration count")
}

func TestRecoverPBEBlockSizeMismatch(t *testing.T) {
	params := pbeParameters{Salt: make([]byte, 8), Iterations: 1}
	paramsBytes, err := asn1.Marshal(params)
	require.NoError(t, err)

	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		EncryptedKey: make([]byte, 7), // not a multiple of 8
	}

	_, err = recoverPBEWithMD5AndDES3CBC(epki, []byte("changeit"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "multiple of block length")
}

func TestRecoverPBEBadASN1Params(t *testing.T) {
	epki := encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: []byte{0x01, 0x02}},
		},
		EncryptedKey: make([]byte, 16),
	}

	_, err := recoverPBEWithMD5AndDES3CBC(epki, []byte("changeit"))
	assert.Error(t, err)
}

// --- ParseWithOptions with nil password (no integrity check) ---

func TestParseWithOptionsNilPassword(t *testing.T) {
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
	jceksData := buildMinimalJCEKS(t, "alias", certDER, password)

	// Parse with nil password → skips integrity check
	ks := new(KeyStore)
	err = ks.Parse(bytes.NewReader(jceksData), nil)
	require.NoError(t, err)

	aliases := ks.ListCerts()
	assert.Len(t, aliases, 1)
}

// --- JKS magic support ---

func TestParseJKSMagic(t *testing.T) {
	// Use JKS magic (0xFEEDFEED) instead of JCEKS magic — same format
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "jks-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	require.NoError(t, err)

	password := "changeit"
	encodedPassword, err := EncodeIntegrityPassword(password)
	require.NoError(t, err)

	var body bytes.Buffer
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jksMagic)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(1)))
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(trustedCertEntryTag)))
	alias := "myalias"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(alias))))
	body.WriteString(alias)
	require.NoError(t, binary.Write(&body, binary.BigEndian, time.Now().UnixMilli()))
	certType := "X.509"
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint16(len(certType))))
	body.WriteString(certType)
	require.NoError(t, binary.Write(&body, binary.BigEndian, uint32(len(certDER))))
	body.Write(certDER)

	h := MakeIntegrityHash(encodedPassword)
	h.Write(body.Bytes())
	body.Write(h.Sum(nil))

	ks, err := LoadFromReader(&body, []byte(password))
	require.NoError(t, err)
	assert.Len(t, ks.ListCerts(), 1)
}

func TestParseReadEntryCountError(t *testing.T) {
	// Valid header but no entry count
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksVersion)))
	// EOF — no entry count

	ks := new(KeyStore)
	err := ks.Parse(&buf, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
	assert.Contains(t, err.Error(), "failed to read entry count")
}

func TestParseReadEntryTagError(t *testing.T) {
	// Valid header + entry count but no tag bytes
	var buf bytes.Buffer
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksMagic)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(jceksVersion)))
	require.NoError(t, binary.Write(&buf, binary.BigEndian, uint32(1))) // 1 entry
	// EOF — no tag

	ks := new(KeyStore)
	err := ks.Parse(&buf, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidJCEKSData)
	assert.Contains(t, err.Error(), "failed to read entry")
}
