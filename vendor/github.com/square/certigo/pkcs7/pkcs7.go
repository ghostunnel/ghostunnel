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

package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

var signedDataIdentifier = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 2})

// SignedDataEnvelope represents a wrapped SignedData
// object found in PEM-encoded PKCS7 blocks.
type SignedDataEnvelope struct {
	Raw        asn1.RawContent
	Type       asn1.ObjectIdentifier
	SignedData SignedData `asn1:"tag:0,explicit,optional"`
}

// SignedData contains signed data and related info.
// Refer to RFC 2315, Section 9.1 for definition of this type.
type SignedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      asn1.RawValue
	Certificates     []asn1.RawValue `asn1:"tag:0,optional,set"`
	RevocationLists  []asn1.RawValue `asn1:"tag:1,optional,set"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// ParseSignedData parses one (or more) signed data blocks from a byte array.
func ParseSignedData(data []byte) ([]*SignedDataEnvelope, error) {
	var err error
	var block *SignedDataEnvelope
	var out []*SignedDataEnvelope

	for rest := data; len(rest) > 0; {
		block, rest, err = parseSignedData(rest)
		if err != nil {
			break
		}
		out = append(out, block)
	}

	return out, err
}

func parseSignedData(data []byte) (*SignedDataEnvelope, []byte, error) {
	var envelope SignedDataEnvelope
	rest, err := asn1.Unmarshal(data, &envelope)
	if err != nil {
		return nil, data, err
	}

	if !signedDataIdentifier.Equal(envelope.Type) {
		return nil, data, fmt.Errorf("unexpected object identifier (was %s, expecting %s)", envelope.Type.String(), signedDataIdentifier.String())
	}

	if envelope.SignedData.Version != 1 {
		return nil, data, fmt.Errorf("unknown version number in signed data block (was %d, expecting 1)", envelope.SignedData.Version)
	}

	return &envelope, rest, nil
}

// ExtractCertificates reads a SignedData type and returns the embedded
// certificates (if present in the structure).
func ExtractCertificates(data []byte) ([]*x509.Certificate, error) {
	blocks, err := ParseSignedData(data)
	if err != nil {
		return nil, err
	}

	certs := []*x509.Certificate{}
	for _, block := range blocks {
		for _, raw := range block.SignedData.Certificates {
			cert, err := x509.ParseCertificate(raw.FullBytes)
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}

	return certs, nil
}
