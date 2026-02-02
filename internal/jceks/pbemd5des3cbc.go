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
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/subtle"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
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

type pbeWithMD5AndDES3CBC struct {
	password   []byte
	rnd        io.Reader
	iterations uint
}

// pbeParameters is the ASN.1 structure stored in the Parameters of the encryptedPrivateKeyInfo algorithm.
type pbeParameters struct {
	Salt       []byte
	Iterations int
}

// PBEWithMD5AndDES3CBC is a PrivateKeyCipher that encrypts a private key using 3DES in CBC mode with PKCS#5 padding,
// using a key and IV derived from the password using several iterations of MD5. This cipher supports only RSA keys.
func PBEWithMD5AndDES3CBC(password []byte, rnd io.Reader, iterations int) (PrivateKeyCipher, error) {
	if err := validatePasswordPBEWithMD5AndDES3CBC(password); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyProtectionParams, err)
	}

	if iterations < 1 {
		return nil, fmt.Errorf("%w: at least one iteration is required", ErrInvalidKeyProtectionParams)
	}

	return &pbeWithMD5AndDES3CBC{
		password:   slices.Clone(password),
		rnd:        rnd,
		iterations: uint(iterations),
	}, nil
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

func (c *pbeWithMD5AndDES3CBC) make3DESParams() (salt []byte, key []byte, iv []byte, err error) {
	salt = make([]byte, pbeMD5DES3CBCSaltLen)
	if _, err := io.ReadFull(c.rnd, salt); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	key, iv = derivePBEWithMD5AndDES3CBCParams(c.password, salt, c.iterations)

	return salt, key, iv, nil
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

func (c *pbeWithMD5AndDES3CBC) encryptPrivateKey(privKey privateKeyInfo) (encryptedPrivateKeyInfo, error) {
	salt, desKey, cbcIV, err := c.make3DESParams()
	if err != nil {
		return encryptedPrivateKeyInfo{}, fmt.Errorf("failed to initialize cipher parameters: %w", err)
	}

	blk, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return encryptedPrivateKeyInfo{}, fmt.Errorf("failed to initialize cipher: %w", err)
	}
	enc := cipher.NewCBCEncrypter(blk, cbcIV)

	encryptedKey, err := asn1.Marshal(privKey)
	if err != nil {
		return encryptedPrivateKeyInfo{}, fmt.Errorf("failed to encode private key info: %w", err)
	}
	encryptedKey = pkcs5Pad(encryptedKey)
	enc.CryptBlocks(encryptedKey, encryptedKey)

	encParams, err := asn1.Marshal(pbeParameters{
		Salt:       salt,
		Iterations: int(c.iterations),
	})
	if err != nil {
		return encryptedPrivateKeyInfo{}, fmt.Errorf("failed to encode encryption parameters: %w", err)
	}

	return encryptedPrivateKeyInfo{
		Algo: pkix.AlgorithmIdentifier{
			Algorithm:  oidPBEWithMD5AndDES3CBC,
			Parameters: asn1.RawValue{FullBytes: encParams},
		},
		EncryptedKey: encryptedKey,
	}, nil
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
