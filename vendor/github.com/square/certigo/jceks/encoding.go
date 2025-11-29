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
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// readBytes reads a byte array from the reader. The encoding provides a 4-byte prefix indicating the number of bytes
// that follow.
func readBytes(r io.Reader, maxLen uint) ([]byte, error) {
	length, err := readInt32(r)
	if err != nil {
		return nil, err
	}
	if length < 0 {
		return nil, ErrInvalidJCEKSData
	}
	if uint(length) > maxLen {
		return nil, fmt.Errorf("%w: data field of size %d bytes exceeds maximimum length of %d",
			ErrJCEKSDataTooLarge, length, maxLen)
	}
	buf := make([]byte, length)
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func writeBytes(w io.Writer, b []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(b))); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}

	return nil
}

func readInt32(r io.Reader) (int32, error) {
	var v int32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}

func writeInt32(w io.Writer, v int32) error {
	return binary.Write(w, binary.BigEndian, v)
}

func readUint32(r io.Reader) (uint32, error) {
	var v uint32
	err := binary.Read(r, binary.BigEndian, &v)
	return v, err
}

func writeUint32(w io.Writer, v uint32) error {
	return binary.Write(w, binary.BigEndian, v)
}

func readDate(r io.Reader) (time.Time, error) {
	var v int64
	err := binary.Read(r, binary.BigEndian, &v)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(v), nil
}

func writeDate(w io.Writer, v time.Time) error {
	return binary.Write(w, binary.BigEndian, v.UnixMilli())
}

// readString reads a length-prefixed modified UTF-8 string.
func readString(r io.Reader) (string, error) {
	var length uint16
	err := binary.Read(r, binary.BigEndian, &length)
	if err != nil {
		return "", err
	}

	return readModifiedUTF8(io.LimitReader(r, int64(length)))
}

func writeString(w io.Writer, str string) error {
	if err := binary.Write(w, binary.BigEndian, uint16(len(str))); err != nil {
		return err
	}
	if err := writeModifiedUTF8(w, str); err != nil {
		return err
	}

	return nil
}

func readCertificate(r io.Reader, maxLen uint) (*x509.Certificate, error) {
	certType, err := readString(r)
	if err != nil {
		return nil, err
	}
	if certType != x509CertTag {
		return nil, fmt.Errorf("%w: unable to handle certificate type: %s", ErrUnsupportedJCEKSData, certType)
	}
	certDER, err := readBytes(r, maxLen)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func writeCertificate(w io.Writer, certDER []byte) error {
	if err := writeString(w, x509CertTag); err != nil {
		return err
	}
	if err := writeBytes(w, certDER); err != nil {
		return err
	}

	return nil
}
