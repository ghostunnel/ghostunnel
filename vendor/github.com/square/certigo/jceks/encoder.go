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
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"time"
)

var (
	ErrNoIntegrityPassword        = errors.New("no integrity password was set")
	ErrInvalidString              = errors.New("string cannot be expressed in JCEKS format")
	ErrInvalidKeyProtectionParams = errors.New("invalid key protection parameters")
	ErrKeyProtectionFailed        = errors.New("key protection failed")
	ErrInvalidCertificates        = errors.New("invalid certificates")
	ErrTooManyEntries             = errors.New("too many entries")
	ErrDuplicateAlias             = errors.New("duplicate alias")
)

// Encoder collects key material and then writes it in JCEKS format when WriteTo is called. The zero value of an Encoder
// is ready to use, but an integrity password must be set by calling SetIntegrityPassword before WriteTo can succeed.
type Encoder struct {
	integrityPassword        []byte
	setIntegrityPassword     bool
	prohibitDuplicateAliases bool
	entryCount               uint
	entries                  [][]byte
	aliasIndices             map[string]int

	_ [0]func() // Incomparable
}

// PrivateKeyCipher represents an encryption method that can protect the confidentiality of private keys in a JCEKS
// file.
type PrivateKeyCipher interface {
	encryptPrivateKey(info privateKeyInfo) (encryptedPrivateKeyInfo, error)
}

// SetIntegrityPassword sets a password that used to verify the integrity of the keystore as a whole. The metadata in
// the keystore can be read without providing the integrity password, but providing it may help to detect modifications
// by processes that do not know the password. A password must be set before the keystore can be written. Password runes
// must be from the basic multilingual plane.
func (e *Encoder) SetIntegrityPassword(password string) error {
	e.setIntegrityPassword = false

	integrityPassword, err := encodeIntegrityPassword(password)
	if err != nil {
		return err
	}

	e.integrityPassword = integrityPassword
	e.setIntegrityPassword = true

	return nil
}

// SetProhibitDuplicateAliases controls whether adding new entries with duplicate aliases is allowed. When prohibit is
// false (the default), newly written aliases overwrite old entries with the same alias. This matches the behavior of
// readers. As an optimization, the overwritten entries will not be written to the output at all. When prohibit is true,
// attempting to add an entry with a duplicate alias returns an error that is ErrDuplicateAlias. Calling this function
// does not change the behavior with respect to previous calls (e.g., setting prohibit to true does not undo any
// previous overwrites).
func (e *Encoder) SetProhibitDuplicateAliases(prohibit bool) {
	e.prohibitDuplicateAliases = prohibit
}

func (e *Encoder) appendEntry(alias string, data []byte) error {
	if e.aliasIndices == nil {
		e.aliasIndices = make(map[string]int)
	}

	if idx, exists := e.aliasIndices[alias]; exists {
		if e.prohibitDuplicateAliases {
			return fmt.Errorf("%w: %q", ErrDuplicateAlias, alias)
		}
		e.entries[idx] = nil
		e.entryCount--
	}

	e.aliasIndices[alias] = len(e.entries)
	e.entries = append(e.entries, data)
	e.entryCount++

	return nil
}

// AddPrivateKeyPKCS1 adds a private key and an associated certificate chain to the keystore. The method uses the given
// PrivateKeyCipher to encrypt the key for storage. The private key must be provided in PKCS#1 private key DER form, and
// the certificates must be provided in X.509 DER form.
func (e *Encoder) AddPrivateKeyPKCS1(alias string, timestamp time.Time,
	keyPKCS1 []byte, certificatesDER [][]byte, cipher PrivateKeyCipher) error {

	protectedKeyInfo, err := cipher.encryptPrivateKey(privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyRSA},
		PrivateKey: keyPKCS1,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrKeyProtectionFailed, err)
	}

	protectedKey, err := asn1.Marshal(protectedKeyInfo)
	if err != nil {
		return fmt.Errorf("failed to encode encrypted private key info: %w", err)
	}

	if err := e.addEncryptedPrivateKey(alias, timestamp, protectedKey, certificatesDER); err != nil {
		return err
	}

	return nil
}

func (e *Encoder) addEncryptedPrivateKey(alias string, timestamp time.Time,
	protectedKey []byte, certificatesDER [][]byte) error {

	if len(alias) > maxAliasLen {
		return fmt.Errorf("%w: alias is too long", ErrInvalidString)
	}
	if len(certificatesDER) > math.MaxInt32 {
		return fmt.Errorf("%w: too many certificates", ErrInvalidCertificates)
	}
	for i, certDER := range certificatesDER {
		if len(certDER) < 1 {
			return fmt.Errorf("%w: certificate %d has no data", ErrInvalidCertificates, i)
		}
		if len(certDER) > math.MaxInt32 {
			return fmt.Errorf("%w: certificate %d has a DER encoding that exceeds JCEKS capacity",
				ErrInvalidCertificates, i)
		}
	}
	if len(protectedKey) > math.MaxInt32 {
		return fmt.Errorf("%w: protected key is too large", ErrKeyProtectionFailed)
	}

	var buf bytes.Buffer

	_ = writeUint32(&buf, privateKeyEntryTag)
	_ = writeString(&buf, alias)
	_ = writeDate(&buf, timestamp)
	_ = writeBytes(&buf, protectedKey)

	_ = writeInt32(&buf, int32(len(certificatesDER)))
	for _, certDER := range certificatesDER {
		_ = writeCertificate(&buf, certDER)
	}

	if err := e.appendEntry(alias, buf.Bytes()); err != nil {
		return err
	}

	return nil
}

// AddTrustedCertificate adds a trusted certificate to the keystore. The certificate is not associated with a private
// key and receives no confidentiality protection. Storing a certificate in the keystore provides a verifiable record of
// trust if the keystore's integrity protection is secure. The certificate must be provided in X.509 DER form.
func (e *Encoder) AddTrustedCertificate(alias string, timestamp time.Time, certDER []byte) error {
	if len(alias) > maxAliasLen {
		return fmt.Errorf("%w: alias is too long", ErrInvalidString)
	}

	var buf bytes.Buffer

	_ = writeUint32(&buf, trustedCertEntryTag)
	_ = writeString(&buf, alias)
	_ = writeDate(&buf, timestamp)
	_ = writeCertificate(&buf, certDER)

	if err := e.appendEntry(alias, buf.Bytes()); err != nil {
		return err
	}

	return nil
}

// AddKeyStore adds the trusted certificates and private keys from an existing keystore to the Encoder. The existing
// keystore's integrity password is ignored. Existing private keys are added to the Encoder without decrypting them, so
// no private key passwords are needed, but any existing problems with the private keys will be preserved.
func (e *Encoder) AddKeyStore(ks *KeyStore) error {
	for alias, tc := range ks.trustedCerts {
		if err := e.AddTrustedCertificate(alias, tc.timestamp, tc.cert.Raw); err != nil {
			return fmt.Errorf("failed to add trusted certificate %q: %w", alias, err)
		}
	}
	for alias, sk := range ks.privateKeys {
		certificatesDER := make([][]byte, 0, len(sk.certs))
		for _, cert := range sk.certs {
			certificatesDER = append(certificatesDER, cert.Raw)
		}
		if err := e.addEncryptedPrivateKey(alias, sk.timestamp, sk.protectedKey, certificatesDER); err != nil {
			return fmt.Errorf("failed to add private key %q: %w", alias, err)
		}
	}

	return nil
}

// counterWriter passes through writes to an underlying io.Writer, but keeps track of the number of bytes written and
// the first error encountered. It simplifies the implementation of multi-write algorithms.
type counterWriter struct {
	w   io.Writer
	n   int64
	err error
}

func (cw *counterWriter) Write(p []byte) (int, error) {
	if cw.err == nil {
		nn, err := cw.w.Write(p)
		cw.n += int64(nn)
		cw.err = err
	}

	return len(p), nil
}

func (cw *counterWriter) Results() (int64, error) {
	return cw.n, cw.err
}

// jceksDigester computes the JCEKS SHA1 integrity protection hash for the JCEKS file written into it.
type jceksDigester struct {
	h hash.Hash
}

func newJCEKSDigester(encodedPassword []byte) *jceksDigester {
	return &jceksDigester{
		h: makeIntegrityHash(encodedPassword),
	}
}

func (j *jceksDigester) Write(p []byte) (n int, err error) {
	return j.h.Write(p)
}

// WriteDigest writes the computed JCEKS integrity hash to the underlying io.Writer.
func (j *jceksDigester) WriteDigest(w io.Writer) error {
	_, err := w.Write(j.h.Sum(nil))

	return err
}

// WriteTo writes a JCEKS file to the given io.Writer. The keystore contains the key material that has been added to the
// Encoder in previous calls.
func (e *Encoder) WriteTo(w io.Writer) (n int64, err error) {
	if !e.setIntegrityPassword {
		return 0, fmt.Errorf("refusing to write JCEKS due to likely bug: %w", ErrNoIntegrityPassword)
	}
	if e.entryCount > math.MaxInt32 {
		return 0, fmt.Errorf("%w: %d entries exceeds JCEKS limit", ErrTooManyEntries, e.entryCount)
	}

	cw := &counterWriter{w: w}
	jd := newJCEKSDigester(e.integrityPassword)
	out := io.MultiWriter(cw, jd)

	_ = writeUint32(out, uint32(jceksMagic))
	_ = writeUint32(out, uint32(jceksVersion))
	_ = writeUint32(out, uint32(e.entryCount))
	for _, entry := range e.entries {
		if len(entry) < 1 {
			continue
		}
		_, _ = out.Write(entry)
	}
	_ = jd.WriteDigest(out)

	return cw.Results()
}
