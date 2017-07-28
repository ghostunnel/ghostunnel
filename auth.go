/*-
 * Copyright 2015 Square Inc.
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

package main

import (
	"crypto/x509"
	"errors"
	"github.com/spiffe/go-spiffe"
	"encoding/pem"
)

func verifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if *serverAllowAll {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CN against --allow-cn flag(s).
	for _, expectedCN := range *serverAllowedCNs {
		if cert.Subject.CommonName == expectedCN {
			return nil
		}
	}

	// Check OUs against --allow-ou flag(s).
	for _, expectedOU := range *serverAllowedOUs {
		for _, clientOU := range cert.Subject.OrganizationalUnit {
			if clientOU == expectedOU {
				return nil
			}
		}
	}

	for _, expectedDNS := range *serverAllowedDNSs {
		for _, clientDNS := range cert.DNSNames {
			if clientDNS == expectedDNS {
				return nil
			}
		}
	}

	for _, expectedIP := range *serverAllowedIPs {
		for _, clientIP := range cert.IPAddresses {
			if expectedIP.Equal(clientIP) {
				return nil
			}
		}
	}

	// Encode the certificate as PEM
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		},
	)

	// Get URIs from the SAN in the certificate
	if len(*serverAllowedURIs) > 0 {
		uris, err := spiffe.GetUrisInSubjectAltName(string(pemdata));
		if err == nil {
			for _, expectedURI := range *serverAllowedURIs {
				for _, clientURI := range uris {
					if clientURI == expectedURI {
						return nil
					}
				}
			}
		} else {
			logger.Printf("error getting URIs from SAN: %s", err)
		}
	}
	return errors.New("unauthorized: invalid principal, or principal not allowed")
}

func verifyPeerCertificateClient(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If none of --verify-cn, --verify-ou, verify-dns-san or verify-ip-san is specified, only hostname verification is performed
	if len(*clientAllowedCNs) == 0 && len(*clientAllowedOUs) == 0 && len(*clientAllowedDNSs) == 0 && len(*clientAllowedIPs) == 0 {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CNs against --verify-cn flag(s).
	for _, expectedCN := range *clientAllowedCNs {
		if cert.Subject.CommonName == expectedCN {
			return nil
		}
	}

	// Check OUs against --verify-ou flag(s).
	for _, expectedOU := range *clientAllowedOUs {
		for _, serverOU := range cert.Subject.OrganizationalUnit {
			if serverOU == expectedOU {
				return nil
			}
		}
	}

	// Check DNSs against --verify-dns-san flag(s).
	for _, expectedDNS := range *clientAllowedDNSs {
		for _, serverDNS := range cert.DNSNames {
			if serverDNS == expectedDNS {
				return nil
			}
		}
	}

	// Check IPs against --verify-ip-san flag(s).
	for _, expectedIP := range *clientAllowedIPs {
		for _, serverIP := range cert.IPAddresses {
			if expectedIP.Equal(serverIP) {
				return nil
			}
		}
	}
	return errors.New("unauthorized: invalid principal, or principal not allowed")
}
