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

// Package jceks parses JCEKS (Java Cryptogaphy Extension Key Store)
// files and extracts keys and certificates. This module only implements
// a fraction of the JCEKS cryptographic protocols. In particular, it
// implements the SHA1 signature verification of the key store and the
// PBEWithMD5AndDES3CBC cipher for encrypting private keys.
package jceks

import (
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
)

var (
	ErrInvalidPassword = errors.New("password is unsupported by JCEKS format")
)

const (
	jceksMagic                 = 0xcececece
	jceksVersion               = 0x02
	jksMagic                   = 0xfeedfeed
	privateKeyEntryTag  uint32 = 1
	trustedCertEntryTag uint32 = 2
	secretKeyEntryTag   uint32 = 3
	x509CertTag                = "X.509"
	jceksIntegrityMagic        = "Mighty Aphrodite"
	maxAliasLen                = 0xFFFF
)

var (
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

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

// encodeIntegrityPassword transforms a password string into the byte sequence that the JCEKS format defines as input to
// the integrity protection hash. The format does not support all possible password strings, so the function returns
// ErrInvalidPassword for invalid passwords.
func encodeIntegrityPassword(password string) ([]byte, error) {
	if len(password) < 1 {
		return nil, fmt.Errorf("%w: empty passwords are not interoperable", ErrInvalidPassword)
	}
	for _, r := range password {
		if r > math.MaxUint16 {
			return nil, fmt.Errorf("%w: password contains unsupported codepoints", ErrInvalidPassword)
		}
	}

	var integrityPassword []byte
	for _, r := range password {
		integrityPassword = binary.BigEndian.AppendUint16(integrityPassword, uint16(r))
	}

	return integrityPassword, nil
}

// makeIntegrityHash initializes the hash function used to check JCEKS file integrity.
func makeIntegrityHash(encodedPassword []byte) hash.Hash {
	h := sha1.New()
	h.Write(encodedPassword)
	h.Write([]byte(jceksIntegrityMagic))

	return h
}
