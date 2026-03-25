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
	"encoding/binary"
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
)

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
