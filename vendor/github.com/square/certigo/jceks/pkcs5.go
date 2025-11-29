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
	"crypto/des"
	"crypto/subtle"
)

func pkcs5Pad(ciphertext []byte) []byte {
	pad := byte(des.BlockSize - len(ciphertext)%des.BlockSize)

	return append(ciphertext, bytes.Repeat([]byte{pad}, int(pad))...)
}

func pkcs5Unpad(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < des.BlockSize {
		return nil, ErrInvalidCiphertext
	}

	pad := ciphertext[len(ciphertext)-1]
	if pad > des.BlockSize {
		return nil, ErrInvalidCiphertext
	}
	if subtle.ConstantTimeCompare(ciphertext[len(ciphertext)-int(pad):], bytes.Repeat([]byte{pad}, int(pad))) != 1 {
		return nil, ErrInvalidCiphertext
	}

	return ciphertext[:len(ciphertext)-int(pad)], nil
}
