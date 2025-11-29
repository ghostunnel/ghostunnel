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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ocsp"
)

type simpleVerifyCert struct {
	Name               string `json:"name"`
	IsSelfSigned       bool   `json:"is_self_signed"`
	PEM                string `json:"pem"`
	signatureAlgorithm x509.SignatureAlgorithm
}

type SimpleVerification struct {
	Error          string               `json:"error,omitempty"`
	OCSPStatus     *ocsp.Response       `json:"ocsp_response,omitempty"`
	OCSPWasStapled bool                 `json:"ocsp_was_stapled,omitempty"`
	OCSPError      string               `json:"ocsp_error,omitempty"`
	Chains         [][]simpleVerifyCert `json:"chains"`
}

type SimpleResult struct {
	Certificates           []*x509.Certificate `json:"certificates"`
	Formats                []string
	VerifyResult           *SimpleVerification `json:"verify_result,omitempty"`
	TLSConnectionState     *tls.ConnectionState
	CertificateRequestInfo *tls.CertificateRequestInfo
}

func (s SimpleResult) MarshalJSON() ([]byte, error) {
	certs := make([]interface{}, len(s.Certificates))
	for i, c := range s.Certificates {
		certs[i] = EncodeX509ToObject(c)
	}

	out := map[string]interface{}{}
	out["certificates"] = certs
	if s.VerifyResult != nil {
		out["verify_result"] = s.VerifyResult
	}
	if s.TLSConnectionState != nil {
		out["tls_connection"] = EncodeTLSToObject(s.TLSConnectionState)
	}
	if s.CertificateRequestInfo != nil {
		encoded, err := EncodeCRIToObject(s.CertificateRequestInfo)
		if err != nil {
			return nil, err
		}
		out["certificate_request_info"] = encoded
	}
	return json.Marshal(out)
}

func caBundle(caPath string) (*x509.CertPool, error) {
	if caPath == "" {
		return nil, nil
	}

	caFile, err := os.Open(caPath)
	if err != nil {
		return nil, fmt.Errorf("error opening CA bundle %s: %w", caPath, err)
	}

	bundle := x509.NewCertPool()
	err = ReadAsX509FromFiles(
		[]*os.File{caFile},
		"",
		func(prompt string) string {
			// TODO: The JDK trust store ships with this password.
			return "changeit"
		},
		func(cert *x509.Certificate, format string, err error) error {
			if err != nil {
				return fmt.Errorf("error parsing CA bundle: %w", err)
			} else {
				bundle.AddCert(cert)
			}
			return nil
		})
	if err != nil {
		return nil, fmt.Errorf("error parsing CA bundle: %w", err)
	}
	return bundle, nil
}

func VerifyChain(certs []*x509.Certificate, ocspStaple []byte, expectedName, caPath string) SimpleVerification {
	result := SimpleVerification{
		Chains:         [][]simpleVerifyCert{},
		OCSPWasStapled: ocspStaple != nil,
	}

	if len(certs) == 0 {
		result.Error = "no certificates found"
		return result
	}

	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}

	roots, err := caBundle(caPath)
	if err != nil {
		result.Error = err.Error() + "\n"
		return result
	}
	// expectedName could be a hostname or could be a SPIFFE ID (spiffe://...)
	// x509 package doesn't support verifying SPIFFE IDs. When we're expecting a SPIFFE ID, we tell
	// Certificate.Verify below to skip name matching, and then we perform our own matching later
	// on.
	spiffeIDExpected := strings.HasPrefix(strings.ToLower(expectedName), "spiffe://")
	var expectedDNSName string
	if !spiffeIDExpected {
		expectedDNSName = expectedName
	}
	opts := x509.VerifyOptions{
		DNSName:       expectedDNSName,
		Roots:         roots,
		Intermediates: intermediates,
	}

	chains, err := certs[0].Verify(opts)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	if spiffeIDExpected {
		// The Verify method above didn't actually verify that the certificate matches the expected
		// SPIFFE ID. We thus perform this check explicitly here.
		err = verifyCertificateSPIFFEIDMatch(certs[0], expectedName)
		if err != nil {
			result.Error = err.Error()
			return result
		}
	}

	for _, chain := range chains {
		status, err := checkOCSP(chain, ocspStaple)
		if err == nil {
			result.OCSPStatus = status
		}
		if err != nil && !errors.Is(err, errSkippedRevocationCheck) {
			result.OCSPError = err.Error()
		}

		aChain := []simpleVerifyCert{}
		for _, cert := range chain {
			aCert := simpleVerifyCert{
				IsSelfSigned:       IsSelfSigned(cert),
				signatureAlgorithm: cert.SignatureAlgorithm,
				PEM:                string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil))),
			}

			aCert.Name = PrintCommonName(cert.Subject)
			aChain = append(aChain, aCert)
		}
		result.Chains = append(result.Chains, aChain)
	}
	return result
}

func fmtCert(cert simpleVerifyCert) string {
	name := cert.Name
	if cert.IsSelfSigned {
		name += green.SprintfFunc()(" [self-signed]")
	}
	for _, alg := range badSignatureAlgorithms {
		if cert.signatureAlgorithm == alg {
			name += red.SprintfFunc()(" [%s]", algString(alg))
			break
		}
	}
	return name
}

func PrintVerifyResult(out io.Writer, result SimpleVerification) {
	if result.Error != "" {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Failed to verify certificate chain:"))
		_, _ = fmt.Fprintf(out, "\t%s\n", result.Error)
		return
	}

	printOCSPStatus(out, result)
	printCertificateChains(out, result)
}

func printCertificateChains(out io.Writer, result SimpleVerification) {
	_, _ = fmt.Fprint(out, green.SprintfFunc()("Found %d valid certificate chain(s):\n", len(result.Chains)))
	for i, chain := range result.Chains {
		_, _ = fmt.Fprintf(out, "[%d] %s\n", i, fmtCert(chain[0]))
		for j, cert := range chain {
			if j == 0 {
				continue
			}
			_, _ = fmt.Fprintf(out, "\t=> %s\n", fmtCert(cert))
		}
	}
}

func printOCSPStatus(out io.Writer, result SimpleVerification) {
	if result.OCSPError != "" {
		_, _ = fmt.Fprint(out, red.SprintlnFunc()("Certificate has OCSP extension, but was unable to check status:"))
		_, _ = fmt.Fprintf(out, "\t%s\n\n", result.OCSPError)
		return
	}

	if result.OCSPStatus != nil {
		status, ok := revocationStatusDescription[result.OCSPStatus.Status]
		if !ok {
			status = "Unknown"
		}

		color, ok := revocationStatusColor[result.OCSPStatus.Status]
		if !ok {
			color = yellow
		}

		wasStapled := ""
		if result.OCSPWasStapled {
			wasStapled = " (was stapled)"
		}

		_, _ = fmt.Fprint(out, color.SprintfFunc()("Checked OCSP status for certificate%s, got:", wasStapled))
		_, _ = fmt.Fprintf(out, "\n\t%s (last update: %s)", status, result.OCSPStatus.ProducedAt.Format(time.RFC822))

		if result.OCSPStatus.Status == ocsp.Revoked {
			reason, ok := revocationReasonDescription[result.OCSPStatus.RevocationReason]
			if !ok {
				reason = "Unknown"
			}

			_, _ = fmt.Fprintf(out, "\n\tWas revoked at %s due to: %s", result.OCSPStatus.RevokedAt.Format(time.RFC822), reason)
		}

		_, _ = fmt.Fprint(out, "\n\n")
	}
}

func verifyCertificateSPIFFEIDMatch(cert *x509.Certificate, expectedSPIFFEID string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md
	uris := cert.URIs
	if len(uris) == 0 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains no URI SANs", expectedSPIFFEID)
	} else if len(uris) > 1 {
		return fmt.Errorf("x509: cannot validate certificate for %s, because it contains %d URIs SANs instead of exactly 1", expectedSPIFFEID, len(uris))
	}

	uri := uris[0]
	actualSPIFFEID := uri.String()
	err := verifySPIFFEIDMatch(expectedSPIFFEID, actualSPIFFEID)
	if err != nil {
		return fmt.Errorf("x509: certificate is valid for %s, not %s: %s", actualSPIFFEID, expectedSPIFFEID, err)
	}

	// Matched
	return nil
}

func verifySPIFFEIDMatch(expected string, actual string) error {
	// Based on https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md
	// SPIFFE ID format: spiffe://trust-domain-name/path
	// * scheme and authority of the URI are case-insensitive
	// * path of the URI is case-sensitive
	//
	// However, as per Trust Domain and Path sections, authority is not supposed to include userinfo
	// and authority's host is supposed to be lower-case and no %-escaped characters. Similarly, no
	// %-escaped stuff in the path.
	//
	// Thus, all we need to do is verify that:
	// 1. both IDs start with "spiffe://" (case-insensitive)
	// 2. both IDs equal (case-sensitive) after the "spiffe://"

	// Verify both have "spiffe" as the scheme (case-insensitive)
	if !strings.HasPrefix(strings.ToLower(expected), "spiffe://") {
		return fmt.Errorf("expected scheme is not \"spiffe\"")
	}
	if !strings.HasPrefix(strings.ToLower(actual), "spiffe://") {
		return fmt.Errorf("actual scheme is not \"spiffe\"")
	}

	// Verify that everything after the scheme equals in a case-sensitive way
	expectedRemainder := expected[len("spiffe://"):]
	actualRemainder := actual[len("spiffe://"):]
	if expectedRemainder != actualRemainder {
		return fmt.Errorf("trust domain and/or path do not match")
	}

	// They match
	return nil
}
