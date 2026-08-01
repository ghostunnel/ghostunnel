/*-
 * Copyright 2026 Ghostunnel
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
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/ghostunnel/ghostunnel/policy"
	"github.com/ghostunnel/ghostunnel/wildcard"
	"github.com/open-policy-agent/opa/v1/rego"
)

// The ACL verification functions run inside every TLS handshake: crypto/tls
// invokes VerifyPeerCertificateServer (server mode) or
// VerifyPeerCertificateClient (client mode) as the VerifyPeerCertificate
// callback after chain validation. These benchmarks measure that
// per-handshake cost for each kind of ACL. Only the server variant is
// benchmarked: the client variant runs the identical checks and differs only
// in its empty-ACL fail-open short-circuit.

// benchChains mirrors the shape of verifiedChains as handed to the callback by
// crypto/tls: only the leaf's parsed fields are consulted by the ACL checks,
// so a synthetic certificate is a faithful stand-in (same approach as
// fakeChains in auth_test.go, but with SPIFFE-style URI SANs to make the URI
// matching representative of real deployments).
var benchURI, _ = url.Parse("spiffe://cluster.local/ns/prod/sa/bench-client")

var benchChains = [][]*x509.Certificate{
	{
		{
			Subject: pkix.Name{
				CommonName:         "bench-client",
				OrganizationalUnit: []string{"ou-one", "ou-two"},
			},
			DNSNames:    []string{"bench-client.example.com"},
			IPAddresses: []net.IP{net.IPv4(10, 0, 0, 1)},
			URIs:        []*url.URL{benchURI},
		},
	},
}

// benchmarkVerifyServer runs the callback once to validate the expected
// outcome, then measures it. wantErr guards against benchmarking a
// misconfigured ACL (e.g. timing the cheap early-return path by mistake).
func benchmarkVerifyServer(b *testing.B, acl ACL, rawCerts [][]byte, chains [][]*x509.Certificate, wantErr bool) {
	b.Helper()
	if err := acl.VerifyPeerCertificateServer(rawCerts, chains); (err != nil) != wantErr {
		b.Fatalf("unexpected verification outcome before measurement: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_ = acl.VerifyPeerCertificateServer(rawCerts, chains)
	}
}

// BenchmarkVerifyPeerCertificateServer measures the per-handshake ACL check
// for each attribute type. The *-match cases measure a single-entry ACL whose
// check succeeds; "deny-miss" is the worst case: a populated ACL of every
// attribute type where nothing matches, so every check list is scanned in
// full before the connection is rejected.
func BenchmarkVerifyPeerCertificateServer(b *testing.B) {
	b.Run("allow-all", func(b *testing.B) {
		benchmarkVerifyServer(b, ACL{AllowAll: true}, nil, benchChains, false)
	})

	b.Run("cn-match", func(b *testing.B) {
		benchmarkVerifyServer(b, ACL{AllowedCNs: []string{"bench-client"}}, nil, benchChains, false)
	})

	b.Run("ou-match", func(b *testing.B) {
		benchmarkVerifyServer(b, ACL{AllowedOUs: []string{"ou-two"}}, nil, benchChains, false)
	})

	b.Run("dns-match", func(b *testing.B) {
		benchmarkVerifyServer(b, ACL{AllowedDNSs: []string{"bench-client.example.com"}}, nil, benchChains, false)
	})

	b.Run("ip-match", func(b *testing.B) {
		benchmarkVerifyServer(b, ACL{AllowedIPs: []net.IP{net.IPv4(10, 0, 0, 1)}}, nil, benchChains, false)
	})

	// URI matching is the only check with real per-handshake work beyond a
	// slice scan: intersectsURI serializes each URI SAN with URL.String()
	// (allocates) and runs a compiled wildcard regexp per matcher. The
	// wildcard package has its own micro-benchmarks; this measures the check
	// as the handshake sees it.
	b.Run("uri-match-literal", func(b *testing.B) {
		acl := ACL{AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("spiffe://cluster.local/ns/prod/sa/bench-client")}}
		benchmarkVerifyServer(b, acl, nil, benchChains, false)
	})

	b.Run("uri-match-wildcard", func(b *testing.B) {
		acl := ACL{AllowedURIs: []wildcard.Matcher{wildcard.MustCompile("spiffe://cluster.local/ns/*/sa/*")}}
		benchmarkVerifyServer(b, acl, nil, benchChains, false)
	})

	b.Run("deny-miss", func(b *testing.B) {
		acl := ACL{
			AllowedCNs:  []string{"other-client", "another-client"},
			AllowedOUs:  []string{"ou-three", "ou-four"},
			AllowedDNSs: []string{"other.example.com", "another.example.com"},
			AllowedIPs:  []net.IP{net.IPv4(10, 0, 0, 2), net.IPv4(10, 0, 0, 3)},
			AllowedURIs: []wildcard.Matcher{
				wildcard.MustCompile("spiffe://cluster.local/ns/staging/sa/*"),
				wildcard.MustCompile("spiffe://other.cluster/**"),
			},
		}
		benchmarkVerifyServer(b, acl, nil, benchChains, true)
	})
}

// BenchmarkVerifyPeerCertificateServerOPA measures the per-handshake cost of
// an OPA policy check: the context.WithTimeout setup, building the input
// document from the certificate, and the rego evaluation itself. OPA is by
// far the most expensive ACL option, so regressions here directly affect
// handshake latency for --allow-policy users. The deny case evaluates the
// same policy to its default-false result; because the other ACL fields are
// empty, the two cases differ only in the certificate contents.
func BenchmarkVerifyPeerCertificateServerOPA(b *testing.B) {
	module := `package policy
	import input
	default allow := false
	allow if {
		input.certificate.Subject.CommonName == "bench-client"
	}
	`
	allowQuery, err := rego.New(
		rego.Query("data.policy.allow"),
		rego.Module("bench.rego", module),
	).PrepareForEval(context.Background())
	if err != nil {
		b.Fatal(err)
	}

	acl := ACL{
		AllowOPAQuery:   policy.WrapForTest(&allowQuery),
		OPAQueryTimeout: 10 * time.Second,
	}

	deniedChains := [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{CommonName: "other-client"},
			},
		},
	}

	b.Run("allow", func(b *testing.B) {
		benchmarkVerifyServer(b, acl, nil, benchChains, false)
	})

	b.Run("deny", func(b *testing.B) {
		benchmarkVerifyServer(b, acl, nil, deniedChains, true)
	})
}

// benchPinCert generates a self-signed ECDSA P-256 certificate and returns
// its DER encoding. It mirrors makePinTestCert in auth_test.go but accepts
// testing.TB so it can be used from benchmarks.
func benchPinCert(tb testing.TB) []byte {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pin-bench"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}
	return certDER
}

// benchSPKIPin computes the digest of a cert's SPKI under the given hash and
// wraps it in a SPKIPin (testing.TB counterpart of spkiPin in auth_test.go).
func benchSPKIPin(tb testing.TB, certDER []byte, hash crypto.Hash) SPKIPin {
	tb.Helper()
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		tb.Fatal(err)
	}
	h := hash.New()
	h.Write(cert.RawSubjectPublicKeyInfo)
	return SPKIPin{hash: hash, digest: h.Sum(nil)}
}

// BenchmarkVerifySPKIPin measures the per-handshake cost of SPKI pin
// verification via VerifyPeerCertificateServer. Unlike the chain-based
// checks, pinning works on the raw DER: every handshake pays a full
// x509.ParseCertificate of the leaf plus one digest per configured pin until
// a match, which dominates this path. The per-algorithm cases use a single
// matching pin; "multi-pin-last" models key rotation (current + backup keys)
// with three pins where only the last one matches, so every configured
// digest is computed.
func BenchmarkVerifySPKIPin(b *testing.B) {
	certDER := benchPinCert(b)
	rawCerts := [][]byte{certDER}

	for _, tc := range []struct {
		name string
		hash crypto.Hash
	}{
		{"sha256", crypto.SHA256},
		{"sha384", crypto.SHA384},
		{"sha512", crypto.SHA512},
	} {
		b.Run(tc.name, func(b *testing.B) {
			acl := ACL{AllowedPins: []SPKIPin{benchSPKIPin(b, certDER, tc.hash)}}
			benchmarkVerifyServer(b, acl, rawCerts, nil, false)
		})
	}

	b.Run("multi-pin-last", func(b *testing.B) {
		acl := ACL{AllowedPins: []SPKIPin{
			{hash: crypto.SHA256, digest: make([]byte, 32)},
			{hash: crypto.SHA256, digest: make([]byte, 32)},
			benchSPKIPin(b, certDER, crypto.SHA256),
		}}
		benchmarkVerifyServer(b, acl, rawCerts, nil, false)
	})
}
