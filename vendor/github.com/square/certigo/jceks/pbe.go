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

package jceks

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

var (
	oidPBEWithMD5AndDES3CBC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 42, 2, 19, 1}
)

type pbeParameters struct {
	Salt       []byte
	Iterations int
}

// Here's how this algorithm works:
//
// 1. Split salt in two halves. If the two halves are identical,
//    invert one of them.
// 2. Concatenate password with each of the halves.
// 3. Digest each concatenation with c iterations, where c is the
//    iterationCount. Concatenate the output from each digest round with the
//    password, and use the result as the input to the next digest operation.
//    The digest algorithm is MD5.
// 4. After c iterations, use the 2 resulting digests as follows:
//    The 16 bytes of the first digest and the 1st 8 bytes of the 2nd digest
//    form the triple DES key, and the last 8 bytes of the 2nd digest form the
//    IV.
func recoverPBEWithMD5AndDES3CBC(
	algo pkix.AlgorithmIdentifier, encryptedKey, password []byte) ([]byte, error) {
	var params pbeParameters
	if _, err := asn1.Unmarshal(algo.Parameters.FullBytes, &params); err != nil {
		return nil, err
	}

	// Convert password to byte array, so that it can be digested.
	passwdBytes := make([]byte, len(password))
	for i := 0; i < len(password); i++ {
		passwdBytes[i] = password[i] & 0x7f
	}

	salt := params.Salt
	if len(salt) != 8 {
		return nil, fmt.Errorf("unexpected salt length: %d", len(salt))
	}

	if bytes.Compare(salt[0:4], salt[4:]) == 0 {
		// First and second half of salt are equal, invert first half.
		for i := 0; i < 2; i++ {
			salt[i], salt[3-i] = salt[3-i], salt[i]
		}
	}

	const keyLen = 24
	const blockSize = des.BlockSize
	derivedKey := make([]byte, keyLen+blockSize)
	// Now digest each half (concatenated with password). For each
	// half, go through the loop as many times as specified by the
	// iteration count parameter (inner for loop).  Concatenate the
	// output from each digest round with the password, and use the
	// result as the input to the next digest operation.
	md := md5.New()
	for i := 0; i < 2; i++ {
		n := len(salt) / 2
		toBeHashed := salt[i*n : (i+1)*n]
		for j := 0; j < params.Iterations; j++ {
			md.Write(toBeHashed)
			md.Write(passwdBytes)
			toBeHashed = md.Sum([]byte{})
			md.Reset()
		}
		copy(derivedKey[i*len(toBeHashed):], toBeHashed)
	}

	cipherKey := derivedKey[0:keyLen]
	iv := derivedKey[keyLen:]

	des3, err := des.NewTripleDESCipher(cipherKey)
	if err != nil {
		return nil, err
	}

	decrypter := cipher.NewCBCDecrypter(des3, iv)
	if (len(encryptedKey) % decrypter.BlockSize()) != 0 {
		return nil, fmt.Errorf("encrypted data must be a multiple of block length: %d %d",
			len(encryptedKey), decrypter.BlockSize())
	}

	decryptedKey := make([]byte, len(encryptedKey))
	decrypter.CryptBlocks(decryptedKey, encryptedKey)
	return decryptedKey, nil
}
