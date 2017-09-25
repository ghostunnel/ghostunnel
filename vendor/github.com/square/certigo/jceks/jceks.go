/*-
 * Copyright 2016 Square Inc.
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

// Package jceks parses JCEKS (Java Cryptogaphy Extension Key Store)
// files and extracts keys and certificates. This module only implements
// a fraction of the JCEKS cryptographic protocols. In particular, it
// implements the SHA1 signature verification of the key store and the
// PBEWithMD5AndDES3CBC cipher for encrypting private keys.
package jceks

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"os"
	"time"
)

const (
	jceksMagic   = 0xcececece
	jceksVersion = 0x02
	jksMagic     = 0xfeedfeed
)

var (
	oidKeyProtector = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1}
	oidPublicKeyRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidPublicKeyEC  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

type encryptedPrivateKeyInfo struct {
	Algo         pkix.AlgorithmIdentifier
	EncryptedKey []byte
}

type privateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type privateKeyEntry struct {
	date       time.Time
	encodedKey []byte
	certs      []*x509.Certificate
}

// From https://golang.org/src/crypto/x509/sec1.go (also: see RFC 5915)
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func (e *privateKeyEntry) String() string {
	return fmt.Sprintf("private-key: %s", e.date)
}

func (e *privateKeyEntry) Recover(password []byte) (crypto.PrivateKey, error) {
	var eKey encryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(e.encodedKey, &eKey)
	if err != nil {
		return nil, err
	}
	var decryptedKey []byte
	switch {
	case eKey.Algo.Algorithm.Equal(oidPBEWithMD5AndDES3CBC):
		decryptedKey, err = recoverPBEWithMD5AndDES3CBC(eKey.Algo, eKey.EncryptedKey, password)
	case eKey.Algo.Algorithm.Equal(oidKeyProtector):
		// JavaSoft proprietary key-protection algorithm (used to protect
		// private keys in the keystore implementation that comes with JDK
		// 1.2). We shouldn't need this.
		fallthrough
	default:
		return nil, fmt.Errorf("unsupported encrypted-private-key algorithm: %v", eKey.Algo.Algorithm)
	}
	if err != nil {
		return nil, err
	}

	var pKey privateKeyInfo
	if _, err := asn1.Unmarshal(decryptedKey, &pKey); err != nil {
		return nil, err
	}
	if pKey.Algo.Algorithm.Equal(oidPublicKeyRSA) {
		return x509.ParsePKCS1PrivateKey(pKey.PrivateKey)
	}
	if pKey.Algo.Algorithm.Equal(oidPublicKeyEC) {
		// In a JCEKS file, the EC private key blob contains only the key itself, without the
		// named curve OID. Instead, the named curve OID is in a separate field (in the algorithm
		// indentifier for the keystore entry). However to parse the EC key properly we need the
		// EC key blob to have the curve OID...
		key := ecPrivateKey{}
		oid := asn1.ObjectIdentifier{}
		// Parse EC private key
		_, err := asn1.Unmarshal(pKey.PrivateKey, &key)
		if err != nil {
			return nil, fmt.Errorf("problem parsing ec key asn.1 struct: %s", err)
		}
		// Parse named curve OID from algorithm identifier
		_, err = asn1.Unmarshal(pKey.Algo.Parameters.FullBytes, &oid)
		if err != nil {
			return nil, fmt.Errorf("problem parsing ec key asn.1 struct: %s", err)
		}
		// Update key to add named curve info, re-marshal, and parse
		key.NamedCurveOID = oid
		raw, _ := asn1.Marshal(key)
		return x509.ParseECPrivateKey(raw)
	}
	return nil, fmt.Errorf("unsupported private-key algorithm: %v", pKey.Algo.Algorithm)
}

type trustedCertEntry struct {
	date time.Time
	cert *x509.Certificate
}

func (e *trustedCertEntry) String() string {
	return fmt.Sprintf("trusted-cert: %s", e.date)
}

// KeyStore maintains a map from alias name to the entry for that
// alias. Entries are currently either privateKeyEntry or
// trustedCertEntry.
type KeyStore struct {
	entries map[string]interface{}
}

// readUTF reads a java encoded UTF-8 string. The encoding provides a
// 2-byte prefix indicating the length of the string.
func readUTF(r io.Reader) (string, error) {
	var length uint16
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return "", err
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// readBytes reads a byte array from the reader. The encoding provides
// a 4-byte prefix indicating the number of bytes which follow.
func readBytes(r io.Reader) ([]byte, error) {
	length, err := readInt32(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func readInt32(r io.Reader) (int32, error) {
	var v int32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}

func readUint32(r io.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}

func readDate(r io.Reader) (time.Time, error) {
	var v int64
	err := binary.Read(r, binary.BigEndian, &v)
	if err != nil {
		return time.Time{}, err
	}
	sec := v / 1000
	nsec := (v - sec*1000) * 1000 * 1000
	return time.Unix(sec, nsec), nil
}

// Returns a SHA1 hash which has been pre-keyed with the specified
// password according to the JCEKS algorithm.
func getPreKeyedHash(password []byte) hash.Hash {
	md := sha1.New()
	buf := make([]byte, len(password)*2)
	for i := 0; i < len(password); i++ {
		buf[i*2+1] = password[i]
	}
	md.Write(buf)
	// Yes, "Mighty Aprhodite" is a constant used by this method.
	md.Write([]byte("Mighty Aphrodite"))
	return md
}

func parseHeader(r io.Reader) (uint32, error) {
	magic, err := readUint32(r)
	if err != nil {
		return 0, err
	}
	if magic != jceksMagic && magic != jksMagic {
		return 0, fmt.Errorf("unexpected magic: %08x != (%08x || %08x)", magic, uint32(jceksMagic), uint32(jksMagic))
	}
	version, err := readUint32(r)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (ks *KeyStore) parsePrivateKey(r io.Reader) error {
	alias, err := readUTF(r)
	if err != nil {
		return err
	}
	entry := &privateKeyEntry{
		certs: []*x509.Certificate{},
	}
	entry.date, err = readDate(r)
	if err != nil {
		return err
	}
	entry.encodedKey, err = readBytes(r)
	if err != nil {
		return err
	}
	nCerts, err := readInt32(r)
	if err != nil {
		return err
	}
	for j := 0; j < int(nCerts); j++ {
		certType, err := readUTF(r)
		if err != nil {
			return err
		}
		if certType != "X.509" {
			return fmt.Errorf("unable to handle certificate type: %s", certType)
		}
		certBytes, err := readBytes(r)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil
		}
		entry.certs = append(entry.certs, cert)
	}
	ks.entries[alias] = entry
	return nil
}

func (ks *KeyStore) parseTrustedCert(r io.Reader) error {
	alias, err := readUTF(r)
	if err != nil {
		return err
	}
	entry := &trustedCertEntry{}
	entry.date, err = readDate(r)
	if err != nil {
		return err
	}

	certType, err := readUTF(r)
	if err != nil {
		return err
	}
	if certType != "X.509" {
		return fmt.Errorf("unable to handle certificate type: %s", certType)
	}
	certBytes, err := readBytes(r)
	if err != nil {
		return err
	}
	entry.cert, err = x509.ParseCertificate(certBytes)
	if err != nil {
		return nil
	}

	ks.entries[alias] = entry
	return nil
}

// Parse parses the key store from the specified reader.
func (ks *KeyStore) Parse(r io.Reader, password []byte) error {
	var md hash.Hash
	if password != nil {
		md = getPreKeyedHash(password)
		r = io.TeeReader(r, md)
	}

	version, err := parseHeader(r)
	if err != nil {
		return err
	}
	if version != jceksVersion {
		return fmt.Errorf("unexpected version: %d != %d", version, jceksVersion)
	}

	count, err := readInt32(r)
	if err != nil {
		return err
	}
	for i := 0; i < int(count); i++ {
		tag, err := readInt32(r)
		if err != nil {
			return err
		}
		switch tag {
		case 1:
			// Private-key entry
			err := ks.parsePrivateKey(r)
			if err != nil {
				return err
			}
		case 2:
			// Trusted-cert entry
			err := ks.parseTrustedCert(r)
			if err != nil {
				return err
			}
		case 3:
			// Secret-key entry
			return fmt.Errorf("unimplemented: Secret-key")
		default:
			return fmt.Errorf("unimplemented tag: %d", tag)
		}
	}

	if md != nil {
		computed := md.Sum([]byte{})
		actual := make([]byte, len(computed))
		_, err := io.ReadFull(r, actual)
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare(computed, actual) != 1 {
			return fmt.Errorf("keystore was tampered with or password was incorrect")
		}
	}

	return nil
}

// GetPrivateKeyAndCerts retrieves the specified private key. Returns
// nil if the private key does not exist or alias points to a non
// private key entry.
func (ks *KeyStore) GetPrivateKeyAndCerts(alias string, password []byte) (
	key crypto.PrivateKey, certs []*x509.Certificate, err error) {

	entry := ks.entries[alias]
	if entry == nil {
		return
	}
	switch t := entry.(type) {
	case *privateKeyEntry:
		if len(t.certs) < 1 {
			return nil, nil, fmt.Errorf("key has no certificates")
		}
		key, err = t.Recover(password)
		if err == nil {
			certs = t.certs
			return
		}
	}
	return
}

// GetCert retrieves the specified certificate. Returns nil if the
// certificate does not exist or alias points to a non certificate
// entry.
func (ks *KeyStore) GetCert(alias string) (*x509.Certificate, error) {
	entry := ks.entries[alias]
	if entry == nil {
		return nil, nil
	}
	switch t := entry.(type) {
	case *trustedCertEntry:
		return t.cert, nil
	}
	return nil, nil
}

// ListPrivateKeys lists the names of the private keys stored in the key store.
func (ks *KeyStore) ListPrivateKeys() []string {
	var r []string
	for k, v := range ks.entries {
		if _, ok := v.(*privateKeyEntry); ok {
			r = append(r, k)
		}
	}
	return r
}

// ListCerts lists the names of the certs stored in the key store.
func (ks *KeyStore) ListCerts() []string {
	var r []string
	for k, v := range ks.entries {
		if _, ok := v.(*trustedCertEntry); ok {
			r = append(r, k)
		}
	}
	return r
}

func (ks *KeyStore) String() string {
	var buf bytes.Buffer
	for k, v := range ks.entries {
		fmt.Fprintf(&buf, "%s\n", k)
		fmt.Fprintf(&buf, "  %s\n", v)
	}
	return buf.String()
}

// LoadFromFile loads the key store from the specified file.
func LoadFromFile(filename string, password []byte) (*KeyStore, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return LoadFromReader(file, password)
}

// LoadFromReader loads the key store from the specified file.
func LoadFromReader(reader io.Reader, password []byte) (*KeyStore, error) {
	ks := &KeyStore{
		entries: make(map[string]interface{}),
	}
	err := ks.Parse(reader, password)
	if err != nil {
		return nil, err
	}
	return ks, err
}
