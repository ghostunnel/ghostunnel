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
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"net"
	"net/url"
	"time"

	"github.com/ghostunnel/ghostunnel/wildcard"
)

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
	AllowedURIs []wildcard.Matcher

	// AllowOPAQuery defines a rego precompiled query, ready to be verified
	// against the client certificate. This is exclusive with all other
	// options.
	AllowOPAQuery *rego.PreparedEvalQuery

	// OPAQueryTimeout sets the timeout for AllowOPAQuery. It has no effect
	// if AllowOPAQuery is nil.
	OPAQueryTimeout time.Duration
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
	if contains(a.AllowedCNs, cert.Subject.CommonName) {
		return nil
	}

	// Check OUs against --allow-ou flag(s).
	if intersects(a.AllowedOUs, cert.Subject.OrganizationalUnit) {
		return nil
	}

	// Check DNS SANs against --allow-dns-san flag(s).
	if intersects(a.AllowedDNSs, cert.DNSNames) {
		return nil
	}

	// Check IP SANs against --allow-dns-san flag(s).
	if intersectsIP(a.AllowedIPs, cert.IPAddresses) {
		return nil
	}

	// Check URI SANs against --allow-uri-san flag(s).
	if intersectsURI(a.AllowedURIs, cert.URIs) {
		return nil
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.OPAQueryTimeout)
		defer cancel()
		input := map[string]interface{}{
			"certificate": cert,
		}
		results, err := a.AllowOPAQuery.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return fmt.Errorf("unauthorized: policy returned error: %w", err)
		}
		if results.Allowed() {
			return nil
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
	if len(a.AllowedCNs) == 0 && len(a.AllowedOUs) == 0 && len(a.AllowedDNSs) == 0 && len(a.AllowedURIs) == 0 && len(a.AllowedIPs) == 0 && a.AllowOPAQuery == nil {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CN against --verify-cn flag(s).
	if contains(a.AllowedCNs, cert.Subject.CommonName) {
		return nil
	}

	// Check OUs against --verify-ou flag(s).
	if intersects(a.AllowedOUs, cert.Subject.OrganizationalUnit) {
		return nil
	}

	// Check DNS SANs against --verify-dns-san flag(s).
	if intersects(a.AllowedDNSs, cert.DNSNames) {
		return nil
	}

	// Check IP SANs against --verify-dns-san flag(s).
	if intersectsIP(a.AllowedIPs, cert.IPAddresses) {
		return nil
	}

	// Check URI SANs against --verify-uri-san flag(s).
	if intersectsURI(a.AllowedURIs, cert.URIs) {
		return nil
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.OPAQueryTimeout)
		defer cancel()
		input := map[string]interface{}{
			"certificate": cert,
		}
		results, err := a.AllowOPAQuery.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return fmt.Errorf("unauthorized: policy returned error: %w", err)
		}
		if results.Allowed() {
			return nil
		}
	}

	return errors.New("unauthorized: invalid principal, or principal not allowed")
}

// Returns true if item is contained in set.
func contains(set []string, item string) bool {
	for _, c := range set {
		if c == item {
			return true
		}
	}
	return false
}

// Returns true if at least one item from left is also contained in right.
func intersects(left, right []string) bool {
	for _, item := range left {
		if contains(right, item) {
			return true
		}
	}
	return false
}

// Returns true if at least one item from left is also contained in right.
func intersectsIP(left, right []net.IP) bool {
	for _, l := range left {
		for _, r := range right {
			if r.Equal(l) {
				return true
			}
		}
	}
	return false
}

// Returns true if at least one item from left is also contained in right.
func intersectsURI(left []wildcard.Matcher, right []*url.URL) bool {
	for _, l := range left {
		for _, r := range right {
			if l.Matches(r.String()) {
				return true
			}
		}
	}
	return false
}
