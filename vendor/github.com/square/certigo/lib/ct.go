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

package lib

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"time"

	cttls "github.com/google/certificate-transparency-go/tls"
	ctx509 "github.com/google/certificate-transparency-go/x509"
	ctutil "github.com/google/certificate-transparency-go/x509util"
)

//go:generate go run github.com/square/certigo/internal/gen-known-logs --out ctlogs.go
//go:generate go fmt ctlogs.go

func parseSCTList(cert *x509.Certificate) []*simpleSCT {
	// ctutil contains a fork of crypto/x509 with support for SCTs. We must re-parse the
	// whole certificate to get at them, so do a quick check to see if the SCT extension
	// is present before re-parsing the cert unnecessarily.
	if !hasSCTs(cert) {
		return nil
	}

	var sctList []*simpleSCT
	if scts, err := ctutil.ParseSCTsFromCertificate(cert.Raw); err == nil {
		for _, sct := range scts {
			id := sct.LogID.KeyID[:]
			ssct := &simpleSCT{
				Version:            uint64(sct.SCTVersion),
				LogID:              id,
				Timestamp:          time.UnixMilli(int64(sct.Timestamp)),
				SignatureAlgorithm: sctSignatureAlg(sct.Signature.Algorithm),
			}
			if log := getLogByID(id); log != nil {
				ssct.LogOperator = log.operator
				ssct.LogURL = log.url
			}
			sctList = append(sctList, ssct)
		}
	}
	return sctList
}

func hasSCTs(cert *x509.Certificate) bool {
	for _, e := range cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier(ctx509.OIDExtensionCTSCT)) {
			return true
		}
	}
	return false
}

func getLogByID(id []byte) *ctLog {
	b64 := base64.StdEncoding.EncodeToString(id)
	return knownLogs[b64]
}

func sctSignatureAlg(alg cttls.SignatureAndHashAlgorithm) simpleSigAlg {
	x509Alg := x509.UnknownSignatureAlgorithm
	switch alg.Signature {
	case cttls.RSA:
		switch alg.Hash {
		case cttls.MD5:
			x509Alg = x509.MD5WithRSA
		case cttls.SHA1:
			x509Alg = x509.SHA1WithRSA
		case cttls.SHA256:
			x509Alg = x509.SHA256WithRSA
		case cttls.SHA384:
			x509Alg = x509.SHA384WithRSA
		case cttls.SHA512:
			x509Alg = x509.SHA512WithRSA
		}
	case cttls.DSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.DSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.DSAWithSHA256
		}
	case cttls.ECDSA:
		switch alg.Hash {
		case cttls.SHA1:
			x509Alg = x509.ECDSAWithSHA1
		case cttls.SHA256:
			x509Alg = x509.ECDSAWithSHA256
		case cttls.SHA384:
			x509Alg = x509.ECDSAWithSHA384
		case cttls.SHA512:
			x509Alg = x509.ECDSAWithSHA512
		}
	}
	return simpleSigAlg(x509Alg)
}
