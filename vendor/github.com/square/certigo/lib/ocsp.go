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
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ocsp"
)

var (
	errSkippedRevocationCheck = errors.New("skipped revocation check")

	revocationStatusColor = map[int]*color.Color{
		ocsp.Good:    green,
		ocsp.Revoked: red,
		ocsp.Unknown: yellow,
	}

	revocationStatusDescription = map[int]string{
		ocsp.Good:    "Good",
		ocsp.Revoked: "Revoked",
		ocsp.Unknown: "Unknown",
	}

	revocationReasonDescription = map[int]string{
		ocsp.Unspecified:          "Unspecified",
		ocsp.KeyCompromise:        "KeyCompromise",
		ocsp.CACompromise:         "CACompromise",
		ocsp.AffiliationChanged:   "AffiliationChanged",
		ocsp.Superseded:           "Superseded",
		ocsp.CessationOfOperation: "CessationOfOperation",
		ocsp.CertificateHold:      "CertificateHold",
		ocsp.RemoveFromCRL:        "RemoveFromCRL",
		ocsp.PrivilegeWithdrawn:   "PrivilegeWithdrawn",
		ocsp.AACompromise:         "AACompromise",
	}

	ocspHttpClient = &http.Client{
		// Set a timeout so we don't block forever on broken servers.
		Timeout: 5 * time.Second,
	}
)

const (
	// We retry multiple times, because OCSP servers are often a bit unreliable.
	maxOCSPValidationRetries = 3
)

func checkOCSP(chain []*x509.Certificate, ocspStaple []byte) (status *ocsp.Response, err error) {
	if len(chain) < 2 {
		// Nothing to check here
		return nil, errSkippedRevocationCheck
	}

	leaf, issuer := chain[0], chain[1]
	if len(leaf.OCSPServer) == 0 {
		return nil, errSkippedRevocationCheck
	}

	retries := maxOCSPValidationRetries
	if len(ocspStaple) > 0 {
		// Don't retry if stapled
		retries = 1
	}

	for i := 0; i < retries; i++ {
		encoded := ocspStaple
		if len(encoded) == 0 {
			encoded, err = fetchOCSP(leaf, issuer)
			if err != nil {
				return nil, err
			}
		}

		status, err = ocsp.ParseResponse(encoded, issuer)
		if err == nil {
			break
		}
	}

	return status, err
}

func fetchOCSP(cert, issuer *x509.Certificate) ([]byte, error) {
	encoded, err := ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failure building request: %s", err)
	}

	// Try all the OCSP servers listed in the certificate
	var lastError error
	for _, server := range cert.OCSPServer {
		// We try both GET and POST requests, because some servers are janky.
		var reqs []*http.Request
		if len(encoded) < 255 {
			// GET only supported for requests with small payloads, so we can stash
			// them in the path. RFC says 255 bytes encoded, but doesn't mention if that
			// refers to the DER-encoded payload before or after base64 is applied. We
			// just assume it's the former and try both GET and POST in case one fails.
			req, err := buildOCSPwithGET(server, encoded)
			if err != nil {
				lastError = err
				continue
			}
			reqs = append(reqs, req)
		}

		// POST should always be supported, but some servers don't like it
		req, err := buildOCSPwithPOST(server, encoded)
		if err != nil {
			lastError = err
			continue
		}
		reqs = append(reqs, req)

		for _, req := range reqs {
			body, err := func() ([]byte, error) {
				resp, err := ocspHttpClient.Do(req)
				if err != nil {
					return nil, err
				}
				defer func() { _ = resp.Body.Close() }()

				if resp.StatusCode != http.StatusOK {
					return nil, fmt.Errorf("unexpected status code, got: %s", resp.Status)
				}

				return io.ReadAll(resp.Body)
			}()
			if err != nil {
				lastError = err
				continue
			}

			return body, nil
		}
	}

	return nil, lastError
}

func buildOCSPwithPOST(server string, encoded []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", server, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	err = req.Write(bytes.NewBuffer(encoded))
	if err != nil {
		return nil, err
	}

	return req, nil
}

func buildOCSPwithGET(server string, encoded []byte) (*http.Request, error) {
	// https://datatracker.ietf.org/doc/html/rfc6960#appendix-A.1
	// GET {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
	url := fmt.Sprintf("%s/%s", server, base64.StdEncoding.EncodeToString(encoded))

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}
