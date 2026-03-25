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
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var errInvalidModifiedUTF8 = errors.New("invalid JCEKS string")

// readModifiedUTF8 reads a string with "modified UTF-8" encoding from the given reader, as specified in Java's
// DataInput class. The function reads until the reader returns EOF, then returns the decoded string. See:
// https://docs.oracle.com/en/java/javase/22/docs/api/java.base/java/io/DataInput.html#modified-utf-8
func readModifiedUTF8(r io.Reader) (string, error) {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReader(r)
	}

	var sb strings.Builder
	buf := make([]byte, 6)
	for {
		var err error
		buf[0], err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				break
			}

			return "", fmt.Errorf("failed to read rune byte 1: %w", err)
		}

		// Basic Latin
		if buf[0] < 0x80 {
			if buf[0] == 0x00 {
				return "", fmt.Errorf("%w: 1-byte NUL is not valid in modified UTF-8", errInvalidModifiedUTF8)
			}
			sb.WriteByte(buf[0])

			continue
		}
		if buf[0]&0b11_000000 == 0b10_000000 {
			return "", fmt.Errorf("%w: invalid first rune byte %02x", errInvalidModifiedUTF8, buf[0])
		}

		buf[1], err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}

			return "", fmt.Errorf("failed to read rune byte 2: %w", err)
		}

		if buf[0]&0b111_00000 == 0b110_00000 {
			if buf[0] == 0xC0 && buf[1] == 0x80 {
				sb.WriteByte(0)
			} else {
				rn, _ := utf8.DecodeRune(buf[:2])
				if rn == utf8.RuneError {
					return "", fmt.Errorf("%w: invalid 2-byte UTF-8 codepoint", errInvalidModifiedUTF8)
				}
				sb.WriteRune(rn)
			}

			continue
		}
		if buf[0]&0b1111_0000 != 0b1110_0000 {
			return "", fmt.Errorf("%w: encountered UTF-8 outside basic multilingual plane",
				errInvalidModifiedUTF8)
		}

		buf[2], err = br.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}

			return "", fmt.Errorf("failed to read rune byte 3: %w", err)
		}

		if buf[0] != 0b1110_1101 || (buf[1]&0b111_00000 != 0b101_00000) {
			rn, _ := utf8.DecodeRune(buf[:3])
			if rn == utf8.RuneError {
				return "", fmt.Errorf("%w: invalid 3-byte UTF-8 codepoint", errInvalidModifiedUTF8)
			}
			sb.WriteRune(rn)

			continue
		}

		// UTF-16 surrogate pair encoded as though the surrogates were UTF-8 codepoints
		for i := 3; i < 6; i++ {
			buf[i], err = br.ReadByte()
			if err != nil {
				if err == io.EOF {
					err = io.ErrUnexpectedEOF
				}

				return "", fmt.Errorf("failed to read rune byte %d: %w", i+1, err)
			}
		}
		var surrogates [2]rune
		for i, rnBytes := range [][]byte{buf[0:3], buf[3:6]} {
			if rnBytes[0] != 0b1110_1101 ||
				rnBytes[1]&0b111_00000 != 0b101_00000 ||
				rnBytes[2]&0b11_000000 != 0b10_000000 {
				return "", fmt.Errorf("%w: invalid modified surrogate %d encoding: %02x",
					errInvalidModifiedUTF8, i, rnBytes)
			}
			surrogates[i] = rune(
				0xd800 |
					uint16(rnBytes[1]&0b000_11111)<<6 |
					uint16(rnBytes[2]&0b00_111111),
			)
		}
		rn := utf16.DecodeRune(surrogates[0], surrogates[1])
		if rn == utf8.RuneError {
			return "", fmt.Errorf("%w: invalid supplementary character", errInvalidModifiedUTF8)
		}
		sb.WriteRune(rn)
	}

	return sb.String(), nil
}
