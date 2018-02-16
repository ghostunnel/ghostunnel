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

package auth

import (
	"crypto/x509"
	"errors"
	"net"

	"github.com/spiffe/go-spiffe/uri"
)

// Logger is used by this package to log messages
type Logger interface {
	Printf(format string, v ...interface{})
}

type Acl struct {
	AllowAll    bool
	AllowedCNs  []string
	AllowedOUs  []string
	AllowedDNSs []string
	AllowedIPs  []net.IP
	AllowedURIs []string
	Logger Logger
}

func (a Acl) VerifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if a.AllowAll {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CN against --allow-cn flag(s).
	for _, expectedCN := range a.AllowedCNs {
		if cert.Subject.CommonName == expectedCN {
			return nil
		}
	}

	// Check OUs against --allow-ou flag(s).
	for _, expectedOU := range a.AllowedOUs {
		for _, clientOU := range cert.Subject.OrganizationalUnit {
			if clientOU == expectedOU {
				return nil
			}
		}
	}

	for _, expectedDNS := range a.AllowedDNSs {
		for _, clientDNS := range cert.DNSNames {
			if clientDNS == expectedDNS {
				return nil
			}
		}
	}

	for _, expectedIP := range a.AllowedIPs {
		for _, clientIP := range cert.IPAddresses {
			if expectedIP.Equal(clientIP) {
				return nil
			}
		}
	}

	// Get URIs from the SAN in the certificate
	if len(a.AllowedURIs) > 0 {
		uris, err := uri.GetURINamesFromCertificate(cert)
		if err == nil {
			for _, expectedURI := range a.AllowedURIs {
				for _, clientURI := range uris {
					if clientURI == expectedURI {
						return nil
					}
				}
			}
		} else {
			a.Logger.Printf("error getting URIs from SAN: %s", err)
		}
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed")
}

func (a Acl) VerifyPeerCertificateClient(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If none of --verify-cn, --verify-ou, verify-dns-san, verify-uri-san or verify-ip-san is specified, only hostname verification is performed
	if len(a.AllowedCNs) == 0 && len(a.AllowedOUs) == 0 && len(a.AllowedDNSs) == 0 && len(a.AllowedURIs) == 0 && len(a.AllowedIPs) == 0 {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CNs against --verify-cn flag(s).
	for _, expectedCN := range a.AllowedCNs {
		if cert.Subject.CommonName == expectedCN {
			return nil
		}
	}

	// Check OUs against --verify-ou flag(s).
	for _, expectedOU := range a.AllowedOUs {
		for _, serverOU := range cert.Subject.OrganizationalUnit {
			if serverOU == expectedOU {
				return nil
			}
		}
	}

	// Check DNSs against --verify-dns-san flag(s).
	for _, expectedDNS := range a.AllowedDNSs {
		for _, serverDNS := range cert.DNSNames {
			if serverDNS == expectedDNS {
				return nil
			}
		}
	}

	// Check IPs against --verify-ip-san flag(s).
	for _, expectedIP := range a.AllowedIPs {
		for _, serverIP := range cert.IPAddresses {
			if expectedIP.Equal(serverIP) {
				return nil
			}
		}
	}

	// Get URIs from the SAN in the certificate
	if len(a.AllowedURIs) > 0 {
		uris, err := uri.GetURINamesFromCertificate(cert)
		if err == nil {
			for _, expectedURI := range a.AllowedURIs {
				for _, serverURI := range uris {
					if serverURI == expectedURI {
						return nil
					}
				}
			}
		} else {
			a.Logger.Printf("error getting URIs from SAN: %s", err)
		}
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed")
}
