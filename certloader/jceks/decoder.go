/*-
 * Originally from github.com/square/certigo/jceks
 *
 * Copyright 2025 Block, Inc.
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
 *
 * Modified for use in ghostunnel.
 */

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
	"slices"
	"time"
)

var (
	errInvalidCiphertext            = errors.New("invalid ciphertext")
	errInvalidJCEKSData             = errors.New("invalid JCEKS data")
	errJCEKSDataTooLarge            = errors.New("JCEKS data too large")
	errUnsupportedJCEKSData         = errors.New("unsupported JCEKS data")
	errIntegrityProtectionViolation = errors.New("integrity protection violation")
	errDecryptionFailed             = errors.New("decryption failed with the given password")
)

const (
	defaultMaxCertBytes       = 20 * 1024 * 1024
	defaultMaxPrivateKeyBytes = defaultMaxCertBytes
)

// KeyStore represents the contents of a parsed JCEKS keystore. It can contain a variety of entries, each identified by
// a unique alias string. Currently, we only support trusted certificate and private key entries. The zero value
// represents an empty keystore that is ready to use, but most callers should use LoadFromReader.
type KeyStore struct {
	trustedCerts map[string]*trustedCertEntry
	privateKeys  map[string]*privateKeyEntry
}

func (ks *KeyStore) clearAlias(alias string) {
	delete(ks.trustedCerts, alias)
	delete(ks.privateKeys, alias)
}

type privateKeyEntry struct {
	timestamp    time.Time
	protectedKey []byte
	certs        []*x509.Certificate
}

type trustedCertEntry struct {
	timestamp time.Time
	cert      *x509.Certificate
}

type parseConfig struct {
	maxCertBytes       uint
	maxPrivateKeyBytes uint
}

type parseOption interface {
	applyParseOption(cfg *parseConfig) error
}

type simpleParseOptionFunc func(cfg *parseConfig)

func (f simpleParseOptionFunc) applyParseOption(cfg *parseConfig) error {
	f(cfg)

	return nil
}

func makeParseConfig(opts ...parseOption) (*parseConfig, error) {
	var cfg parseConfig
	for _, opt := range opts {
		err := opt.applyParseOption(&cfg)
		if err != nil {
			return nil, err
		}
	}

	if cfg.maxCertBytes == 0 {
		cfg.maxCertBytes = defaultMaxCertBytes
	}
	if cfg.maxPrivateKeyBytes == 0 {
		cfg.maxPrivateKeyBytes = defaultMaxPrivateKeyBytes
	}

	return &cfg, nil
}

func withMaxCertificateBytes(maxBytes uint) parseOption {
	return simpleParseOptionFunc(func(cfg *parseConfig) {
		cfg.maxCertBytes = maxBytes
	})
}

func withMaxPrivateKeyBytes(maxBytes uint) parseOption {
	return simpleParseOptionFunc(func(cfg *parseConfig) {
		cfg.maxPrivateKeyBytes = maxBytes
	})
}

// Parse parses the key store from the specified reader using default settings.
func (ks *KeyStore) Parse(r io.Reader, password []byte) error {
	return ks.parseWithOptions(r, password)
}

func (ks *KeyStore) parseWithOptions(r io.Reader, password []byte, options ...parseOption) error {
	ks.trustedCerts = make(map[string]*trustedCertEntry)
	ks.privateKeys = make(map[string]*privateKeyEntry)

	cfg, err := makeParseConfig(options...)
	if err != nil {
		return fmt.Errorf("failed to configure parser: %w", err)
	}

	var md hash.Hash
	if password != nil {
		encodedPassword, err := EncodeIntegrityPassword(string(password))
		if err != nil {
			return fmt.Errorf("encoding integrity password: %w", err)
		}
		md = MakeIntegrityHash(encodedPassword)
		r = io.TeeReader(r, md)
	}

	version, err := parseHeader(r)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidJCEKSData, err)
	}
	if version != jceksVersion {
		return fmt.Errorf("%w: unexpected version: %d != %d",
			errInvalidJCEKSData, version, jceksVersion)
	}

	count, err := readInt32(r)
	if err != nil {
		return fmt.Errorf("%w: failed to read entry count", errInvalidJCEKSData)
	}
	for i := 0; i < int(count); i++ {
		tag, err := readUint32(r)
		if err != nil {
			return fmt.Errorf("%w: failed to read entry %d tag", errInvalidJCEKSData, i)
		}
		switch tag {
		case privateKeyEntryTag:
			err := ks.parsePrivateKey(r, cfg)
			if err != nil {
				return fmt.Errorf("%w: failed to parse private key entry %d: %w", errInvalidJCEKSData, i, err)
			}
		case trustedCertEntryTag:
			err := ks.parseTrustedCert(r, cfg)
			if err != nil {
				return fmt.Errorf("%w: failed to parse certificate entry %d: %w", errInvalidJCEKSData, i, err)
			}
		case secretKeyEntryTag:
			return fmt.Errorf("%w: file contains a secret key entry", errUnsupportedJCEKSData)
		default:
			return fmt.Errorf("%w: unknown entry tag %d", errUnsupportedJCEKSData, tag)
		}
	}

	if md != nil {
		computed := md.Sum([]byte{})
		actual := make([]byte, len(computed))
		_, err := io.ReadFull(r, actual)
		if err != nil {
			return fmt.Errorf("%w: failed to read integrity checksum: %w", errInvalidJCEKSData, err)
		}
		if subtle.ConstantTimeCompare(computed, actual) != 1 {
			return fmt.Errorf("%w: keystore was tampered with or password was incorrect",
				errIntegrityProtectionViolation)
		}
	}

	return nil
}

// GetPrivateKeyAndCerts retrieves the specified private key.
func (ks *KeyStore) GetPrivateKeyAndCerts(alias string, password []byte) (
	key crypto.PrivateKey, certs []*x509.Certificate, err error) {

	entry, ok := ks.privateKeys[alias]
	if !ok {
		return nil, nil, nil
	}

	if len(entry.certs) < 1 {
		return nil, nil, fmt.Errorf("%w: key has no certificates", errInvalidJCEKSData)
	}
	key, err = entry.Recover(password)
	if err != nil {
		return nil, nil, fmt.Errorf("recovering private key %q: %w", alias, err)
	}

	return key, entry.certs, nil
}

// GetCert retrieves the specified certificate.
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

// LoadFromReader loads the key store from the specified reader.
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
		return 0, fmt.Errorf("reading magic: %w", err)
	}
	if magic != jceksMagic && magic != jksMagic {
		return 0, fmt.Errorf("unexpected magic: %08x != (%08x || %08x)",
			magic, uint32(jceksMagic), uint32(jksMagic))
	}
	version, err := readUint32(r)
	if err != nil {
		return 0, fmt.Errorf("reading version: %w", err)
	}
	return version, nil
}

func (ks *KeyStore) parsePrivateKey(r io.Reader, cfg *parseConfig) error {
	alias, err := readString(r)
	if err != nil {
		return fmt.Errorf("reading alias: %w", err)
	}
	entry := &privateKeyEntry{
		certs: []*x509.Certificate{},
	}
	entry.timestamp, err = readDate(r)
	if err != nil {
		return fmt.Errorf("reading timestamp: %w", err)
	}
	entry.protectedKey, err = readBytes(r, cfg.maxPrivateKeyBytes)
	if err != nil {
		return fmt.Errorf("reading protected key: %w", err)
	}
	nCerts, err := readInt32(r)
	if err != nil {
		return fmt.Errorf("reading certificate count: %w", err)
	}
	for j := 0; j < int(nCerts); j++ {
		cert, err := readCertificate(r, cfg.maxCertBytes)
		if err != nil {
			return fmt.Errorf("reading certificate %d: %w", j, err)
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
		return fmt.Errorf("reading alias: %w", err)
	}
	entry := &trustedCertEntry{}
	entry.timestamp, err = readDate(r)
	if err != nil {
		return fmt.Errorf("reading timestamp: %w", err)
	}

	entry.cert, err = readCertificate(r, cfg.maxCertBytes)
	if err != nil {
		return fmt.Errorf("reading certificate: %w", err)
	}

	ks.clearAlias(alias)
	ks.trustedCerts[alias] = entry

	return nil
}

func (e *privateKeyEntry) Recover(password []byte) (crypto.PrivateKey, error) {
	var eKey encryptedPrivateKeyInfo
	_, err := asn1.Unmarshal(e.protectedKey, &eKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse private key as DER: %w", errInvalidJCEKSData, err)
	}

	if !eKey.Algo.Algorithm.Equal(oidPBEWithMD5AndDES3CBC) {
		return nil, fmt.Errorf("%w: unsupported encrypted-private-key algorithm: %v",
			errUnsupportedJCEKSData, eKey.Algo.Algorithm)
	}

	privKey, err := recoverPBEWithMD5AndDES3CBC(eKey, password)
	if err != nil {
		return nil, errDecryptionFailed
	}

	// EC needs special handling: re-inject curve OID from algorithm parameters
	if privKey.Algo.Algorithm.Equal(oidPublicKeyEC) {
		key := ecPrivateKey{}
		oid := asn1.ObjectIdentifier{}
		_, err := asn1.Unmarshal(privKey.PrivateKey, &key)
		if err != nil {
			return nil, errDecryptionFailed
		}
		_, err = asn1.Unmarshal(privKey.Algo.Parameters.FullBytes, &oid)
		if err != nil {
			return nil, errDecryptionFailed
		}
		key.NamedCurveOID = oid
		raw, err := asn1.Marshal(key)
		if err != nil {
			return nil, errDecryptionFailed
		}

		return x509.ParseECPrivateKey(raw)
	}

	// RSA, ED25519, and anything else PKCS#8 supports: marshal as PKCS#8 and parse
	pkcs8, err := asn1.Marshal(privKey)
	if err != nil {
		return nil, errDecryptionFailed
	}
	sk, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, errDecryptionFailed
	}
	return sk, nil
}
