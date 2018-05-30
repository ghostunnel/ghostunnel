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
)

// Logger is used by this package to log messages
type Logger interface {
	Printf(format string, v ...interface{})
}

// ACL represents an access control list for mutually-authenticated TLS connections.
// These options are disjunctive, if at least one attribute matches access will be granted.
type ACL struct {
	// AllowAll will allow all authenticated pricipals. If this option is set,
	// all other options are ignored as all principals with valid certificates
	// will be allowed no matter the subject.
	AllowAll bool
	// AllowCNs lists common names that should be allowed access. If a principal
	// has a valid certificate with at least one of these CNs, we grant access.
	AllowedCNs []string
	// AllowOUs lists organizational units that should be allowed access. If a
	// principal has a valid certificate with at least one of these OUs, we grant
	// access.
	AllowedOUs []string
	// AllowDNSs lists DNS SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these DNS SANs, we grant
	// access.
	AllowedDNSs []string
	// AllowIPs lists IP SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these IP SANs, we grant
	// access.
	AllowedIPs []net.IP
	// AllowURIs lists URI SANs that should be allowed access. If a principal
	// has a valid certificate with at least one of these URI SANs, we grant
	// access.
	AllowedURIs []string
	// Logger is used to log authorization decisions.
	Logger Logger
}

// VerifyPeerCertificateServer is an implementation of VerifyPeerCertificate
// for crypto/tls.Config for servers terminating TLS connections that will
// enforce access controls based on the given ACL. If the given ACL is empty,
// no clients will be allowed (fails closed).
func (a ACL) VerifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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

	for _, expectedURI := range a.AllowedURIs {
		for _, clientURI := range cert.URIs {
			if clientURI.String() == expectedURI {
				return nil
			}
		}
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed")
}

// VerifyPeerCertificateClient is an implementation of VerifyPeerCertificate
// for crypto/tls.Config for clients initiating TLS connections that will
// validate the server certificate based on the given ACL. If the ACL is empty,
// all servers will be allowed (this function assumes that DNS name verification
// has already taken place, and therefore fails open).
func (a ACL) VerifyPeerCertificateClient(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If the ACL is empty, only hostname verification is performed. The hostname
	// verification happens in crypto/tls itself, so we can skip our checks here.
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

	for _, expectedURI := range a.AllowedURIs {
		for _, clientURI := range cert.URIs {
			if clientURI.String() == expectedURI {
				return nil
			}
		}
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed")
}
