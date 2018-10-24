/*-
 * Copyright 2018 Square Inc.
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

package lib

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ocsp"
)

var (
	skippedRevocationCheck = errors.New("skipped revocation check")

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
	if len(chain) <= 1 {
		// Nothing to check here
		return nil, skippedRevocationCheck
	}

	retries := maxOCSPValidationRetries
	if len(ocspStaple) > 0 {
		// Don't retry if stapled
		retries = 1
	}

	var issuer *x509.Certificate
	for i := 0; i < retries; i++ {
		encoded := ocspStaple
		if len(encoded) == 0 {
			encoded, _, err = fetchOCSP(chain)
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

func fetchOCSP(chain []*x509.Certificate) ([]byte, *x509.Certificate, error) {
	var lastError error
	for _, issuer := range chain[1:] {
		encoded, err := ocsp.CreateRequest(chain[0], issuer, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failure building request: %s", err)
		}

		// Try all the OCSP servers listed in the certificate
		for _, server := range issuer.OCSPServer {
			// We try both GET and POST requests, because some servers are janky.
			reqs := []*http.Request{}
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
				resp, err := ocspHttpClient.Do(req)
				if err != nil {
					lastError = err
					continue
				}

				if resp.StatusCode != http.StatusOK {
					lastError = fmt.Errorf("unexpected status code, got: %s", resp.Status)
					continue
				}

				body, err := ioutil.ReadAll(resp.Body)
				defer resp.Body.Close()
				if err != nil {
					lastError = err
					continue
				}

				return body, issuer, nil
			}
		}
	}

	return nil, nil, lastError
}

func buildOCSPwithPOST(server string, encoded []byte) (*http.Request, error) {
	req, err := http.NewRequest("POST", server, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Write(bytes.NewBuffer(encoded))

	return req, nil
}

func buildOCSPwithGET(server string, encoded []byte) (*http.Request, error) {
	if !strings.HasSuffix(server, "/") {
		server = server + "/"
	}

	req, err := http.NewRequest("GET", server+base64.StdEncoding.EncodeToString(encoded), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", "application/ocsp-response")

	return req, nil
}
