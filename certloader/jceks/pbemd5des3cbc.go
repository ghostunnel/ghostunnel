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
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/subtle"
	"encoding/asn1"
	"fmt"
	"slices"
)

var (
	oidPBEWithMD5AndDES3CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
)

const (
	pbeMD5DES3CBCSaltLen     = 8
	pbeMD5DES3CBCHalfSaltLen = pbeMD5DES3CBCSaltLen / 2
	pbeMD5DES3CBCKeyLen      = 3 * (64 / 8)
)

// pbeParameters is the ASN.1 structure stored in the Parameters of the encryptedPrivateKeyInfo algorithm.
type pbeParameters struct {
	Salt       []byte
	Iterations int
}

func derivePBEWithMD5AndDES3CBCParams(password []byte, salt []byte, iterations uint) (key []byte, iv []byte) {
	initState := slices.Clone(salt)
	if subtle.ConstantTimeCompare(initState[:pbeMD5DES3CBCHalfSaltLen], initState[pbeMD5DES3CBCHalfSaltLen:]) == 1 {
		slices.Reverse(initState[:pbeMD5DES3CBCHalfSaltLen])
	}

	hashChain := func(state []byte) []byte {
		h := md5.New()
		for range iterations {
			h.Write(state)
			h.Write(password)
			state = h.Sum(state[:0])
			h.Reset()
		}

		return state
	}
	state := append(hashChain(initState[:pbeMD5DES3CBCHalfSaltLen]), hashChain(initState[pbeMD5DES3CBCHalfSaltLen:])...)

	return state[:pbeMD5DES3CBCKeyLen], state[pbeMD5DES3CBCKeyLen:]
}

func validatePasswordPBEWithMD5AndDES3CBC(password []byte) error {
	if len(password) < 1 {
		return fmt.Errorf("%w: empty passwords are not interoperable", ErrInvalidPassword)
	}
	for _, b := range password {
		if b < 0x20 || b > 0x7E {
			return fmt.Errorf("%w: invalid characters", ErrInvalidPassword)
		}
	}

	return nil
}

func recoverPBEWithMD5AndDES3CBC(protectedKeyInfo encryptedPrivateKeyInfo, password []byte) (privateKeyInfo, error) {
	var params pbeParameters
	if _, err := asn1.Unmarshal(protectedKeyInfo.Algo.Parameters.FullBytes, &params); err != nil {
		return privateKeyInfo{}, err
	}
	encryptedKey := protectedKeyInfo.EncryptedKey

	if err := validatePasswordPBEWithMD5AndDES3CBC(password); err != nil {
		return privateKeyInfo{}, err
	}

	salt := params.Salt
	if len(salt) != pbeMD5DES3CBCSaltLen {
		return privateKeyInfo{}, fmt.Errorf("unexpected salt length: %d", len(salt))
	}

	iterations := params.Iterations
	if iterations < 1 {
		return privateKeyInfo{}, fmt.Errorf("unexpected iteration count: %d", iterations)
	}

	desKey, cbcIV := derivePBEWithMD5AndDES3CBCParams(password, salt, uint(iterations))

	blk, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return privateKeyInfo{}, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	dec := cipher.NewCBCDecrypter(blk, cbcIV)
	if (len(encryptedKey) % dec.BlockSize()) != 0 {
		return privateKeyInfo{}, fmt.Errorf("encrypted data must be a multiple of block length: %d %d",
			len(encryptedKey), dec.BlockSize())
	}

	decryptedKey := make([]byte, len(encryptedKey))
	dec.CryptBlocks(decryptedKey, encryptedKey)
	decryptedKey, err = pkcs5Unpad(decryptedKey)
	if err != nil {
		return privateKeyInfo{}, err
	}

	var privKey privateKeyInfo
	if _, err := asn1.Unmarshal(decryptedKey, &privKey); err != nil {
		return privateKeyInfo{}, fmt.Errorf("failed to unmarshal private key: %w", err)
	}

	return privKey, nil
}
