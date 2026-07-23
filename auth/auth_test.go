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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/stretchr/testify/assert"
)

var sanURI, _ = url.Parse("scheme://valid/path")

var fakeChains = [][]*x509.Certificate{
	{
		{
			Subject: pkix.Name{
				CommonName:         "gopher",
				OrganizationalUnit: []string{"triangle", "circle"},
			},
			DNSNames:    []string{"circle"},
			IPAddresses: []net.IP{net.IPv4(192, 168, 99, 100)},
			URIs:        []*url.URL{sanURI},
		},
	},
}

func TestAuthorizeNotVerified(t *testing.T) {
	testACL := ACL{
		AllowAll: true,
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, nil), "conn w/o cert should be rejected")
}

func TestAuthorizeReject(t *testing.T) {
	testACL := ACL{
		AllowedCNs:  []string{"test"},
		AllowedOUs:  []string{"test"},
		AllowedDNSs: []string{"test"},
		AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("test")},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "should reject cert w/o matching CN/OU")
}

func TestAuthorizeAllowAll(t *testing.T) {
	testACL := ACL{
		AllowAll: true,
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-all should always allow authed clients")
}

func TestAuthorizeAllowCN(t *testing.T) {
	testACL := ACL{
		AllowedCNs: []string{"gopher"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-cn should allow clients with matching CN")
}

func TestAuthorizeAllowOU(t *testing.T) {
	testACL := ACL{
		AllowedOUs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-ou should allow clients with matching OU")
}

func TestAuthorizeAllowDNS(t *testing.T) {
	testACL := ACL{
		AllowedDNSs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-dns-san should allow clients with matching DNS SAN")
}

func TestAuthorizeAllowIP(t *testing.T) {
	testACL := ACL{
		AllowedIPs: []net.IP{net.IPv4(192, 168, 99, 100)},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-ip-san should allow clients with matching IP SAN")
}

func TestAuthorizeAllowURI(t *testing.T) {
	testACL := ACL{
		AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("scheme://valid/path")},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "allow-uri-san should allow clients with matching URI SAN")
}

func TestAuthorizeRejectURI(t *testing.T) {
	testACL := ACL{
		AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("scheme://invalid/path")},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "should reject cert w/o matching URI")
}

func TestAuthorizeOPARejectCommonName(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		input.certificate.Subject.CommonName == "gopher NOT"
	}
	`
	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy on different CN should be rejected")
}

func TestAuthorizeOPAAcceptCommonName(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		input.certificate.Subject.CommonName == "gopher"
	}
	`
	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy validates CN should pass")
}

func TestAuthorizeOPAAcceptDNSn(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.DNSNames[_] == "circle"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy validates testing DNS names")
}

func TestAuthorizeOPAAcceptURIs(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.URIs[_].Scheme == "scheme"
		input.certificate.URIs[_].Host == "valid"
		input.certificate.URIs[_].Path == "/path"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy validates testing URIs")
}

func TestAuthorizeOPAAcceptOneOU(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.Subject.OrganizationalUnit[_] == "triangle"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy validates one OU")
}

func TestAuthorizeOPARejectAllOU(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.Subject.OrganizationalUnit[_] == "no existing OU"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.NotNil(t, testACL.VerifyPeerCertificateServer(nil, fakeChains), "Rego policy rejects none OU")
}

func TestVerifyAllowEmpty(t *testing.T) {
	testACL := ACL{}

	// For VerifyPeerCertificateClient, we perform hostname verification
	// and skip ACLs if the ACL is empty (i.e. no flag has been set to verify
	// any attributes of the server peer certificate).
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "empty client ACL skips extra checks")
}

func TestVerifyAllowCN(t *testing.T) {
	testACL := ACL{
		AllowedCNs: []string{"gopher"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-cn should allow servers with matching CN")
}

func TestVerifyAllowOU(t *testing.T) {
	testACL := ACL{
		AllowedOUs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-ou should allow servers with matching OU")
}

func TestVerifyAllowDNS(t *testing.T) {
	testACL := ACL{
		AllowedDNSs: []string{"circle"},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-dns-san should allow servers with matching DNS SAN")
}

func TestVerifyAllowIP(t *testing.T) {
	testACL := ACL{
		AllowedIPs: []net.IP{net.IPv4(192, 168, 99, 100)},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-ip-san should allow servers with matching IP SAN")
}

func TestVerifyRejectCN(t *testing.T) {
	testACL := ACL{
		AllowedCNs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching CN")
}

func TestVerifyRejectOU(t *testing.T) {
	testACL := ACL{
		AllowedOUs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching OU")
}

func TestVerifyRejectDNS(t *testing.T) {
	testACL := ACL{
		AllowedDNSs: []string{"test"},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching DNS SAN")
}

func TestVerifyRejectIP(t *testing.T) {
	testACL := ACL{
		AllowedIPs: []net.IP{net.IPv4(1, 1, 1, 1)},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching IP SAN")
}

func TestVerifyAllowURI(t *testing.T) {
	testACL := ACL{
		AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("scheme://valid/path")},
	}

	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "verify-uri-san should allow clients with matching URI SAN")
}

func TestVerifyRejectURI(t *testing.T) {
	testACL := ACL{
		AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("scheme://invalid/path")},
	}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "should reject cert w/o matching URI")
}

func TestVerifyNoVerifiedChains(t *testing.T) {
	testACL := ACL{}

	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, nil), "should reject if no verified chains")
}

func TestVerifyOPARejectCommonName(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		input.certificate.Subject.CommonName == "gopher NOT"
	}
	`
	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy on different CN should be rejected")
}

func TestVerifyOPAAcceptCommonName(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		input.certificate.Subject.CommonName == "gopher"
	}
	`
	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy validates CN should pass")
}

func TestVerifyOPAAcceptDNSn(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.DNSNames[_] == "circle"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy validates testing DNS names")
}

func TestVerifyOPAAcceptURIs(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.URIs[_].Scheme == "scheme"
		input.certificate.URIs[_].Host == "valid"
		input.certificate.URIs[_].Path == "/path"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy validates testing URIs")
}

func TestVerifyOPAAcceptOneOU(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.Subject.OrganizationalUnit[_] == "triangle"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.Nil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy validates one OU")
}

func TestVerifyOPARejectAllOU(t *testing.T) {
	module := `package policy
	import input
	default allow := false

	allow if {
		input.certificate.Subject.OrganizationalUnit[_] == "no existing OU"
	}
	`

	allowQuery, _ := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
	).PrepareForEval(context.Background())

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	assert.NotNil(t, testACL.VerifyPeerCertificateClient(nil, fakeChains), "Rego policy rejects none OU")
}

// makePinTestCert generates a self-signed ECDSA certificate and returns its
// DER encoding along with the SHA-256 SPKI pin digest (the raw 32-byte hash).
func makePinTestCert(t *testing.T) (certDER []byte, sha256Digest []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err = x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return certDER, hash[:]
}

// spkiPin is a test helper that computes the digest of a cert's SPKI under the
// given hash and wraps it in a SPKIPin.
func spkiPin(t *testing.T, certDER []byte, hash crypto.Hash) SPKIPin {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)
	h := hash.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return SPKIPin{hash: hash, digest: h.Sum(nil)}
}

func TestParseSPKIPins(t *testing.T) {
	// Empty input yields no pins and no error.
	pins, err := ParseSPKIPins(nil)
	assert.Nil(t, err)
	assert.Nil(t, pins)

	sha256Digest := base64.StdEncoding.EncodeToString(make([]byte, 32))
	sha384Digest := base64.StdEncoding.EncodeToString(make([]byte, 48))
	sha512Digest := base64.StdEncoding.EncodeToString(make([]byte, 64))

	// A single valid sha256 pin parses.
	pins, err = ParseSPKIPins([]string{"sha256:" + sha256Digest})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pins))
	assert.Equal(t, crypto.SHA256, pins[0].hash)
	assert.Equal(t, 32, len(pins[0].digest))

	// sha384 and sha512 are also accepted, with their respective digest sizes.
	pins, err = ParseSPKIPins([]string{"sha384:" + sha384Digest})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pins))
	assert.Equal(t, crypto.SHA384, pins[0].hash)
	assert.Equal(t, 48, len(pins[0].digest))

	pins, err = ParseSPKIPins([]string{"sha512:" + sha512Digest})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pins))
	assert.Equal(t, crypto.SHA512, pins[0].hash)
	assert.Equal(t, 64, len(pins[0].digest))

	// Multiple valid pins all parse, including mixed algorithms.
	pins, err = ParseSPKIPins([]string{"sha256:" + sha256Digest, "sha512:" + sha512Digest})
	assert.Nil(t, err)
	assert.Equal(t, 2, len(pins))

	// The algorithm prefix is case-insensitive.
	pins, err = ParseSPKIPins([]string{"SHA256:" + sha256Digest})
	assert.Nil(t, err)
	assert.Equal(t, 1, len(pins))
	assert.Equal(t, crypto.SHA256, pins[0].hash)

	// Missing algorithm prefix is rejected.
	_, err = ParseSPKIPins([]string{sha256Digest})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "expected format <algo>:<base64-digest>")

	// Unknown algorithm is rejected.
	_, err = ParseSPKIPins([]string{"sha1:" + base64.StdEncoding.EncodeToString(make([]byte, 20))})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
	assert.Contains(t, err.Error(), "sha256, sha384, sha512")

	// Invalid base64 is rejected.
	_, err = ParseSPKIPins([]string{"sha256:not valid base64 @@@"})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "unable to decode base64")

	// Wrong digest length is rejected.
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	_, err = ParseSPKIPins([]string{"sha256:" + short})
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "expected 32 bytes for sha256, got 16")

	// If any pin in the list is invalid, the whole call fails.
	_, err = ParseSPKIPins([]string{"sha256:" + sha256Digest, "sha256:" + short})
	assert.NotNil(t, err)
}

func TestAuthorizePinMatch(t *testing.T) {
	certDER, digest := makePinTestCert(t)

	pin := SPKIPin{hash: crypto.SHA256, digest: digest}
	testACL := ACL{AllowedPins: []SPKIPin{pin}}

	err := testACL.VerifyPeerCertificateServer([][]byte{certDER}, nil)
	assert.Nil(t, err, "matching pin should allow connection")

	err = testACL.VerifyPeerCertificateClient([][]byte{certDER}, nil)
	assert.Nil(t, err, "matching pin should allow connection")
}

// TestAuthorizePinNonSha256 verifies that the generalized hash path works: a
// pin configured with sha512 matches a cert whose SPKI is hashed with sha512.
func TestAuthorizePinNonSha256(t *testing.T) {
	certDER, _ := makePinTestCert(t)

	pin := spkiPin(t, certDER, crypto.SHA512)
	testACL := ACL{AllowedPins: []SPKIPin{pin}}

	assert.Nil(t, testACL.VerifyPeerCertificateServer([][]byte{certDER}, nil),
		"sha512 pin should match")
	assert.Nil(t, testACL.VerifyPeerCertificateClient([][]byte{certDER}, nil),
		"sha512 pin should match")
}

// TestAuthorizePinMultiple verifies that when several pins are configured (e.g.
// a current and a backup key), a peer matching any one of them is accepted.
func TestAuthorizePinMultiple(t *testing.T) {
	certDER, digest := makePinTestCert(t)
	otherPin := SPKIPin{hash: crypto.SHA256, digest: make([]byte, 32)} // a backup/rotation pin that does not match
	matchedPin := SPKIPin{hash: crypto.SHA256, digest: digest}

	// SPKIPin matches whether it is first or last in the list, and the list may
	// mix algorithms.
	mixedAlgo := spkiPin(t, certDER, crypto.SHA384)
	for _, pins := range [][]SPKIPin{
		{matchedPin, otherPin},
		{otherPin, matchedPin},
		{otherPin, mixedAlgo},
	} {
		testACL := ACL{AllowedPins: pins}
		err := testACL.VerifyPeerCertificateServer([][]byte{certDER}, nil)
		assert.Nil(t, err, "connection should be allowed when one of the pins matches")
		err = testACL.VerifyPeerCertificateClient([][]byte{certDER}, nil)
		assert.Nil(t, err, "connection should be allowed when one of the pins matches")
	}
}

// TestAuthorizePinExpiredCert locks in the intentional behavior that SPKI
// pinning authenticates by public key alone: an expired certificate whose key
// matches the pin is still accepted, because the validity period is not
// checked. If this ever changes, it must be a deliberate decision.
func TestAuthorizePinExpiredCert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	// A certificate that became valid two hours ago and expired one hour ago.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-test-expired"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-1 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NoError(t, err)

	pin := spkiPin(t, certDER, crypto.SHA256)
	testACL := ACL{AllowedPins: []SPKIPin{pin}}

	assert.Nil(t, testACL.VerifyPeerCertificateServer([][]byte{certDER}, nil),
		"expired cert with matching pin should be accepted (expiry is not checked)")
	assert.Nil(t, testACL.VerifyPeerCertificateClient([][]byte{certDER}, nil),
		"expired cert with matching pin should be accepted (expiry is not checked)")
}

func TestAuthorizePinMismatch(t *testing.T) {
	certDER, _ := makePinTestCert(t)

	wrongPin := SPKIPin{hash: crypto.SHA256, digest: make([]byte, 32)}
	testACL := ACL{AllowedPins: []SPKIPin{wrongPin}}

	err := testACL.VerifyPeerCertificateServer([][]byte{certDER}, nil)
	assert.NotNil(t, err, "mismatched pin should reject connection")
	assert.Contains(t, err.Error(), "unable to verify pin")

	err = testACL.VerifyPeerCertificateClient([][]byte{certDER}, nil)
	assert.NotNil(t, err, "mismatched pin should reject connection")
	assert.Contains(t, err.Error(), "unable to verify pin")
}

func TestAuthorizePinNoRawCerts(t *testing.T) {
	pin := SPKIPin{hash: crypto.SHA256, digest: make([]byte, 32)}
	testACL := ACL{AllowedPins: []SPKIPin{pin}}

	err := testACL.VerifyPeerCertificateServer(nil, nil)
	assert.NotNil(t, err, "no raw certs should reject connection")

	err = testACL.VerifyPeerCertificateClient(nil, nil)
	assert.NotNil(t, err, "no raw certs should reject connection")
}

// TestAuthorizePinMalformedDER covers the parse-error branch of verifySPKIPin: a
// non-empty rawCerts entry that is not a valid certificate is rejected rather
// than panicking. This closes the one uncovered line in verifySPKIPin.
func TestAuthorizePinMalformedDER(t *testing.T) {
	pin := SPKIPin{hash: crypto.SHA256, digest: make([]byte, 32)}
	testACL := ACL{AllowedPins: []SPKIPin{pin}}

	err := testACL.VerifyPeerCertificateServer([][]byte{[]byte("not a certificate")}, nil)
	assert.NotNil(t, err, "malformed cert DER should reject connection")
	assert.Contains(t, err.Error(), "unable to parse certificate")

	err = testACL.VerifyPeerCertificateClient([][]byte{[]byte("not a certificate")}, nil)
	assert.NotNil(t, err, "malformed cert DER should reject connection")
	assert.Contains(t, err.Error(), "unable to parse certificate")
}

func TestAuthorizeOPAEvalError(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		to_number(input.certificate.Subject.CommonName) == 1
	}
	`
	allowQuery, err := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	assert.NoError(t, err, "policy should compile cleanly; error must occur at Eval time")

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	err = testACL.VerifyPeerCertificateServer(nil, fakeChains)
	assert.Error(t, err, "Rego eval error should surface as an unauthorized error")
	assert.Contains(t, err.Error(), "unauthorized: unable to evaluate policy:",
		"server should wrap eval error with unable-to-evaluate-policy prefix")
}

func TestVerifyOPAEvalError(t *testing.T) {
	module := `package policy
	import input
	default allow := false
	allow if {
		to_number(input.certificate.Subject.CommonName) == 1
	}
	`
	allowQuery, err := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("test.rego", module),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(context.Background())
	assert.NoError(t, err, "policy should compile cleanly; error must occur at Eval time")

	testACL := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}
	err = testACL.VerifyPeerCertificateClient(nil, fakeChains)
	assert.Error(t, err, "Rego eval error should surface as an unauthorized error")
	assert.Contains(t, err.Error(), "unauthorized: unable to evaluate policy:",
		"client should wrap eval error with unable-to-evaluate-policy prefix")
}
