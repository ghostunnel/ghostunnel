// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jceks

import (
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"time"
)

var (
	ErrInvalidCiphertext            = errors.New("invalid ciphertext")
	ErrInvalidJCEKSData             = errors.New("invalid JCEKS data")
	ErrJCEKSDataTooLarge            = errors.New("JCEKS data too large")
	ErrUnsupportedJCEKSData         = errors.New("unsupported JCEKS data")
	ErrIntegrityProtectionViolation = errors.New("integrity protection violation")
	ErrDecryptionFailed             = errors.New("decryption failed with the given password")
)

const (
	defaultMaxCertBytes       = 20 * 1024 * 1024
	defaultMaxPrivateKeyBytes = defaultMaxCertBytes
)

// KeyStore represents the contents of a parsed JCEKS keystore. It can contain a variety of entries, each identified by
// a unique alias string. Currently, we only support trusted certificate and private key entries. The zero value
// represents an empty keystore that is ready to use, but most callers should immediately call Parse, ParseWithOptions,
// or create a KeyStore using LoadFromFile or LoadFromReader.
type KeyStore struct {
	trustedCerts map[string]*trustedCertEntry
	privateKeys  map[string]*privateKeyEntry
}

func (ks *KeyStore) clearAlias(alias string) {
	// JCEKS convention is that the alias namespace is shared across all entry types, and the last entry with a
	// duplicate alias wins, so we need to clear duplicate aliases from all potential types when parsing a new one.
	delete(ks.trustedCerts, alias)
	delete(ks.privateKeys, alias)
}

type privateKeyEntry struct {
	timestamp    time.Time
	protectedKey []byte
	certs        []*x509.Certificate
}

func (e *privateKeyEntry) String() string {
	return fmt.Sprintf("private-key: %s", e.timestamp)
}

type trustedCertEntry struct {
	timestamp time.Time
	cert      *x509.Certificate
}

func (e *trustedCertEntry) String() string {
	return fmt.Sprintf("trusted-cert: %s", e.timestamp)
}

type parseConfig struct {
	maxCertBytes       uint
	maxPrivateKeyBytes uint
}

// ParseOption modifies the behavior of KeyStore.ParseWithOptions.
type ParseOption interface {
	applyParseOption(cfg *parseConfig) error
}

type simpleParseOptionFunc func(cfg *parseConfig)

func (f simpleParseOptionFunc) applyParseOption(cfg *parseConfig) error {
	f(cfg)

	return nil
}

func makeParseConfig(opts ...ParseOption) (*parseConfig, error) {
	var cfg parseConfig
	for _, opt := range opts {
		err := opt.applyParseOption(&cfg)
		if err != nil {
			return nil, err
		}
	}

	if cfg.maxCertBytes <= 0 {
		cfg.maxCertBytes = defaultMaxCertBytes
	}
	if cfg.maxPrivateKeyBytes <= 0 {
		cfg.maxPrivateKeyBytes = defaultMaxPrivateKeyBytes
	}

	return &cfg, nil
}

// WithMaxCertificateBytes sets the maximum size of certificates contained in the JCEKS file in bytes. This limit
// applies to the DER encoding of the certificates. When maxBytes is zero or the option is not provided, the parser
// uses an unspecified default that is suitable for most certificates. The default is not part of the API and may change
// in future minor release versions.
func WithMaxCertificateBytes(maxBytes uint) ParseOption {
	return simpleParseOptionFunc(func(cfg *parseConfig) {
		cfg.maxCertBytes = maxBytes
	})
}

// WithMaxPrivateKeyBytes sets the maximum size of private keys contained in the JCEKS file in bytes. This limit applies
// to the encrypted, encoded private key data, which has a format that varies by key type. Certificates attached to the
// private key individually adhere to the certificate size limit, and are unaffected by this option. When maxBytes is
// zero or the option is not provided, the parser uses an unspecified default that is suitable for most private keys.
// The default is not part of the API and may change in future minor release versions.
func WithMaxPrivateKeyBytes(maxBytes uint) ParseOption {
	return simpleParseOptionFunc(func(cfg *parseConfig) {
		cfg.maxPrivateKeyBytes = maxBytes
	})
}

// Parse parses the key store from the specified reader using default settings. It is equivalent to calling
// ParseWithOptions without any options.
func (ks *KeyStore) Parse(r io.Reader, password []byte) error {
	return ks.ParseWithOptions(r, password)
}

// ParseWithOptions parses the key store from the specified reader.
func (ks *KeyStore) ParseWithOptions(r io.Reader, password []byte, options ...ParseOption) error {
	ks.trustedCerts = make(map[string]*trustedCertEntry)
	ks.privateKeys = make(map[string]*privateKeyEntry)

	cfg, err := makeParseConfig(options...)
	if err != nil {
		return fmt.Errorf("failed to configure parser: %w", err)
	}

	var md hash.Hash
	if password != nil {
		encodedPassword, err := encodeIntegrityPassword(string(password))
		if err != nil {
			return err
		}
		md = makeIntegrityHash(encodedPassword)
		r = io.TeeReader(r, md)
	}

	version, err := parseHeader(r)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidJCEKSData, err)
	}
	if version != jceksVersion {
		return fmt.Errorf("%w: unexpected version: %d != %d",
			ErrInvalidJCEKSData, version, jceksVersion)
	}

	count, err := readInt32(r)
	if err != nil {
		return fmt.Errorf("%w: failed to read entry count", ErrInvalidJCEKSData)
	}
	for i := 0; i < int(count); i++ {
		tag, err := readUint32(r)
		if err != nil {
			return fmt.Errorf("%w: failed to read entry %d tag", ErrInvalidJCEKSData, i)
		}
		switch tag {
		case privateKeyEntryTag:
			err := ks.parsePrivateKey(r, cfg)
			if err != nil {
				return fmt.Errorf("%w: failed to parse private key entry %d: %w", ErrInvalidJCEKSData, i, err)
			}
		case trustedCertEntryTag:
			err := ks.parseTrustedCert(r, cfg)
			if err != nil {
				return fmt.Errorf("%w: failed to parse certificate entry %d: %w", ErrInvalidJCEKSData, i, err)
			}
		case secretKeyEntryTag:
			return fmt.Errorf("%w: file contains a secret key entry", ErrUnsupportedJCEKSData)
		default:
			return fmt.Errorf("%w: unknown entry tag %d", ErrUnsupportedJCEKSData, tag)
		}
	}

	if md != nil {
		computed := md.Sum([]byte{})
		actual := make([]byte, len(computed))
		_, err := io.ReadFull(r, actual)
		if err != nil {
			return fmt.Errorf("%w: failed to read integrity checksum: %w", ErrInvalidJCEKSData, err)
		}
		if subtle.ConstantTimeCompare(computed, actual) != 1 {
			return fmt.Errorf("%w: keystore was tampered with or password was incorrect",
				ErrIntegrityProtectionViolation)
		}
	}

	return nil
}

// GetPrivateKeyAndCerts retrieves the specified private key. Returns nil if the private key does not exist or alias
// points to a non-private key entry.
func (ks *KeyStore) GetPrivateKeyAndCerts(alias string, password []byte) (
	key crypto.PrivateKey, certs []*x509.Certificate, err error) {

	entry, ok := ks.privateKeys[alias]
	if !ok {
		return nil, nil, nil
	}

	if len(entry.certs) < 1 {
		return nil, nil, fmt.Errorf("%w: key has no certificates", ErrInvalidJCEKSData)
	}
	key, err = entry.Recover(password)
	if err != nil {
		return nil, nil, err
	}

	return key, entry.certs, nil
}

// GetCert retrieves the specified certificate. Returns nil if the certificate does not exist or alias points to a
// non-certificate entry.
func (ks *KeyStore) GetCert(alias string) (*x509.Certificate, error) {
	entry, ok := ks.trustedCerts[alias]
	if !ok {
		return nil, nil
	}

	return entry.cert, nil
}

// ListPrivateKeys lists the names of the private keys stored in the key store.
func (ks *KeyStore) ListPrivateKeys() []string {
	return slices.Sorted(maps.Keys(ks.privateKeys))
}

// ListCerts lists the names of the certs stored in the key store.
func (ks *KeyStore) ListCerts() []string {
	return slices.Sorted(maps.Keys(ks.trustedCerts))
}

func (ks *KeyStore) String() string {
	m := make(map[string]fmt.Stringer, len(ks.trustedCerts)+len(ks.privateKeys))
	for k, v := range ks.trustedCerts {
		m[k] = v
	}
	for k, v := range ks.privateKeys {
		m[k] = v
	}

	var buf strings.Builder
	for _, k := range slices.Sorted(maps.Keys(m)) {
		_, _ = fmt.Fprintf(&buf, "%s\n", k)
		_, _ = fmt.Fprintf(&buf, "  %s\n", m[k])
	}

	return buf.String()
}

// LoadFromFile loads the key store from the specified file.
func LoadFromFile(filename string, password []byte) (*KeyStore, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()

	ks, err := LoadFromReader(file, password)
	if err != nil {
		return nil, err
	}

	err = file.Close()
	file = nil
	if err != nil {
		return nil, err
	}

	return ks, nil
}

// LoadFromReader loads the key store from the specified file.
func LoadFromReader(reader io.Reader, password []byte) (*KeyStore, error) {
	ks := new(KeyStore)
	err := ks.Parse(reader, password)
	if err != nil {
		return nil, err
	}

	return ks, err
}

func parseHeader(r io.Reader) (uint32, error) {
	magic, err := readUint32(r)
	if err != nil {
		return 0, err
	}
	if magic != jceksMagic && magic != jksMagic {
		return 0, fmt.Errorf("unexpected magic: %08x != (%08x || %08x)",
			magic, uint32(jceksMagic), uint32(jksMagic))
	}
	version, err := readUint32(r)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (ks *KeyStore) parsePrivateKey(r io.Reader, cfg *parseConfig) error {
	alias, err := readString(r)
	if err != nil {
		return err
	}
	entry := &privateKeyEntry{
		certs: []*x509.Certificate{},
	}
	entry.timestamp, err = readDate(r)
	if err != nil {
		return err
	}
	entry.protectedKey, err = readBytes(r, cfg.maxPrivateKeyBytes)
	if err != nil {
		return err
	}
	nCerts, err := readInt32(r) // Sun reference implementation uses a signed int here
	if err != nil {
		return err
	}
	for j := 0; j < int(nCerts); j++ {
		cert, err := readCertificate(r, cfg.maxCertBytes)
		if err != nil {
			return nil
		}
		entry.certs = append(entry.certs, cert)
	}

	ks.clearAlias(alias)
	ks.privateKeys[alias] = entry

	return nil
}

func (ks *KeyStore) parseTrustedCert(r io.Reader, cfg *parseConfig) error {
	alias, err := readString(r)
	if err != nil {
		return err
	}
	entry := &trustedCertEntry{}
	entry.timestamp, err = readDate(r)
	if err != nil {
		return err
	}

	entry.cert, err = readCertificate(r, cfg.maxCertBytes)
	if err != nil {
		return err
	}

	ks.clearAlias(alias)
	ks.trustedCerts[alias] = entry

	return nil
}

func (e *privateKeyEntry) Recover(password []byte) (crypto.PrivateKey, error) {
	var eKey encryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(e.protectedKey, &eKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse private key as DER: %w", ErrInvalidJCEKSData, err)
	}

	if !eKey.Algo.Algorithm.Equal(oidPBEWithMD5AndDES3CBC) {
		return nil, fmt.Errorf("%w: unsupported encrypted-private-key algorithm: %v",
			ErrUnsupportedJCEKSData, eKey.Algo.Algorithm)
	}

	// From this point on, intentionally do not reveal detailed info from errors, for security

	privKey, err := recoverPBEWithMD5AndDES3CBC(eKey, password)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	if privKey.Algo.Algorithm.Equal(oidPublicKeyRSA) {
		sk, err := x509.ParsePKCS1PrivateKey(privKey.PrivateKey)
		if err != nil {
			return nil, ErrDecryptionFailed
		}

		return sk, nil
	}
	if privKey.Algo.Algorithm.Equal(oidPublicKeyEC) {
		// In a JCEKS file, the EC private key blob contains only the key itself, without the named curve OID. Instead,
		// the named curve OID is in a separate field (in the algorithm identifier for the keystore entry). However, to
		// parse the EC key properly, we need the EC key blob to have the curve OID...
		key := ecPrivateKey{}
		oid := asn1.ObjectIdentifier{}
		// Parse EC private key
		_, err := asn1.Unmarshal(privKey.PrivateKey, &key)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		// Parse named curve OID from algorithm identifier
		_, err = asn1.Unmarshal(privKey.Algo.Parameters.FullBytes, &oid)
		if err != nil {
			return nil, ErrDecryptionFailed
		}
		// Update key to add named curve info, re-marshal, and parse
		key.NamedCurveOID = oid
		raw, _ := asn1.Marshal(key)

		return x509.ParseECPrivateKey(raw)
	}

	return nil, fmt.Errorf("%w: unsupported private-key algorithm", ErrUnsupportedJCEKSData)
}
