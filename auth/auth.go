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
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	// pin.hash.New() panics unless the hash implementation is linked into the
	// binary. These blank imports register the SHA-2 hashes referenced by
	// supportedSPKIPinHashes (crypto/sha512 registers SHA-384 as well as SHA-512),
	// so pinning does not depend on some other package importing them first.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/open-policy-agent/opa/v1/rego"
)

// ACL represents an access control list for mutually-authenticated TLS connections.
// These options are disjunctive, if at least one attribute matches access will be granted.
type ACL struct {
	// AllowAll will allow all authenticated principals. If this option is set,
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
	AllowOPAQuery policy.Policy

	// OPAQueryTimeout sets the timeout for AllowOPAQuery. It has no effect
	// if AllowOPAQuery is nil.
	OPAQueryTimeout time.Duration

	// AllowedPins holds SPKI pins (see SPKIPin and ParseSPKIPins) of the expected peer's
	// SubjectPublicKeyInfo. When non-empty, verification uses out-of-band key
	// pinning (in the style of RFC 7858 section 4.2): the peer is authenticated
	// solely by requiring the leaf certificate's SPKI hash to match one of these
	// pins, and the certificate chain, validity period, and hostname are not
	// verified. Multiple pins may be supplied so that a current and a backup
	// key can both be accepted during key rotation. This is mutually exclusive
	// with all other ACL fields.
	AllowedPins []SPKIPin
}

// supportedSPKIPinHashes maps the algorithm name accepted in the "<algo>:<digest>"
// pin syntax to its crypto.Hash.
var supportedSPKIPinHashes = map[string]crypto.Hash{
	"sha256": crypto.SHA256,
	"sha384": crypto.SHA384,
	"sha512": crypto.SHA512,
}

// SPKIPin is a single SPKI pin: a hash algorithm and the expected digest of the
// peer's DER-encoded SubjectPublicKeyInfo. The digest is compared in constant
// time (see verifySPKIPin).
type SPKIPin struct {
	hash   crypto.Hash
	digest []byte
}

// ParseSPKIPins parses SPKI pins of the form "<algo>:<base64-digest>" (e.g.
// "sha256:..."). The algorithm prefix is required and must be one of the
// supported SHA-2 hashes. The digest must be base64-decodable and exactly
// hash.Size() bytes. Returns nil if pins is empty. Any invalid entry rejects
// the whole set, so malformed pins surface at startup rather than at
// listen/dial time.
func ParseSPKIPins(pins []string) ([]SPKIPin, error) {
	if len(pins) == 0 {
		return nil, nil
	}
	parsed := make([]SPKIPin, 0, len(pins))
	for _, p := range pins {
		pin, err := parseSPKIPin(p)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, pin)
	}
	return parsed, nil
}

func parseSPKIPin(s string) (SPKIPin, error) {
	algo, digest, ok := strings.Cut(s, ":")
	if !ok {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: expected format <algo>:<base64-digest>", s)
	}
	// Accept the algorithm prefix case-insensitively (e.g. "SHA256" as well as
	// "sha256"); supportedSPKIPinHashes is keyed on the lowercase form.
	algo = strings.ToLower(algo)
	hash, ok := supportedSPKIPinHashes[algo]
	if !ok {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: unsupported hash algorithm %q (supported: sha256, sha384, sha512)", s, algo)
	}
	// Any hash added to supportedSPKIPinHashes must also be linked in (see the
	// blank crypto/sha* imports above), otherwise hash.New() would panic
	// mid-handshake in verifySPKIPin. Reject here so a missing import fails
	// cleanly at flag-parse time instead.
	if !hash.Available() {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: hash algorithm %q is not available in this build", s, algo)
	}
	raw, err := base64.StdEncoding.DecodeString(digest)
	if err != nil {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: base64 decode failed: %w", s, err)
	}
	if len(raw) != hash.Size() {
		return SPKIPin{}, fmt.Errorf("invalid pin %q: expected %d bytes for %s, got %d", s, hash.Size(), algo, len(raw))
	}
	return SPKIPin{hash: hash, digest: raw}, nil
}

// PinningEnabled reports whether this ACL authenticates peers via SPKI pinning
// (see AllowedPins). It is the single source of truth for pin mode: when it returns
// true, the transport MUST disable normal certificate verification
// (InsecureSkipVerify on clients, RequireAnyClientCert on servers) so that
// verifySPKIPin becomes the sole authentication check, and VerifyPeerCertificate{Server,Client}
// enforce the pin. Keeping both decisions derived from this one predicate
// prevents the transport and the verifier from drifting out of sync.
func (a ACL) PinningEnabled() bool {
	return len(a.AllowedPins) > 0
}

// verifySPKIPin checks whether the leaf certificate in rawCerts matches one of the
// configured SPKI pins. It is called when pinning is enabled, bypassing all
// chain-based verification. Each pin's hash is computed independently of the
// others, so multiple pins configured with different algorithms are all
// evaluated. The pin set is scanned sequentially and short-circuits on the
// first match; the pin set is operator configuration (not a secret), so only
// the individual digest comparison is constant-time (via subtle.ConstantTimeCompare).
func (a ACL) verifySPKIPin(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("unauthorized: no certificate presented")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("unauthorized: failed to parse certificate: %w", err)
	}

	spki := cert.RawSubjectPublicKeyInfo
	for _, pin := range a.AllowedPins {
		h := pin.hash.New()
		h.Write(spki)
		if subtle.ConstantTimeCompare(h.Sum(nil), pin.digest) == 1 {
			return nil
		}
	}

	return errors.New("unauthorized: pin verification failed")
}

// VerifyPeerCertificateServer is an implementation of VerifyPeerCertificate
// for crypto/tls.Config for servers terminating TLS connections that will
// enforce access controls based on the given ACL. If the given ACL is empty,
// no clients will be allowed (fails closed).
func (a ACL) VerifyPeerCertificateServer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if a.PinningEnabled() {
		return a.verifySPKIPin(rawCerts)
	}

	if len(verifiedChains) == 0 {
		return errors.New("unauthorized: invalid principal, or principal not allowed")
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if a.AllowAll {
		return nil
	}

	cert := verifiedChains[0][0]

	// Check CN against --allow-cn flag(s).
	if slices.Contains(a.AllowedCNs, cert.Subject.CommonName) {
		return nil
	}

	// Check OUs against --allow-ou flag(s).
	if intersects(a.AllowedOUs, cert.Subject.OrganizationalUnit) {
		return nil
	}

	// Check DNS SANs against --allow-dns flag(s).
	if intersects(a.AllowedDNSs, cert.DNSNames) {
		return nil
	}

	// Check IP SANs against --allow-ip flag(s).
	if intersectsIP(a.AllowedIPs, cert.IPAddresses) {
		return nil
	}

	// Check URI SANs against --allow-uri flag(s).
	if intersectsURI(a.AllowedURIs, cert.URIs) {
		return nil
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.OPAQueryTimeout)
		defer cancel()
		input := map[string]any{
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
	if a.PinningEnabled() {
		return a.verifySPKIPin(rawCerts)
	}

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
	if slices.Contains(a.AllowedCNs, cert.Subject.CommonName) {
		return nil
	}

	// Check OUs against --verify-ou flag(s).
	if intersects(a.AllowedOUs, cert.Subject.OrganizationalUnit) {
		return nil
	}

	// Check DNS SANs against --verify-dns flag(s).
	if intersects(a.AllowedDNSs, cert.DNSNames) {
		return nil
	}

	// Check IP SANs against --verify-ip flag(s).
	if intersectsIP(a.AllowedIPs, cert.IPAddresses) {
		return nil
	}

	// Check URI SANs against --verify-uri flag(s).
	if intersectsURI(a.AllowedURIs, cert.URIs) {
		return nil
	}

	// Check against OPA
	if a.AllowOPAQuery != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.OPAQueryTimeout)
		defer cancel()
		input := map[string]any{
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

// Returns true if at least one item from left is also contained in right.
func intersects(left, right []string) bool {
	for _, item := range left {
		if slices.Contains(right, item) {
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
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	serialized := make([]string, len(right))
	for i, r := range right {
		serialized[i] = r.String()
	}
	for _, l := range left {
		if slices.ContainsFunc(serialized, l.Matches) {
			return true
		}
	}
	return false
}
