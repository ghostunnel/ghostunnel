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
	"crypto/x509/pkix"
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
	allow = true {
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
	allow = true {
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

	allow = true {
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

	allow {
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

	allow {
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

	allow {
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
	allow = true {
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
	allow = true {
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

	allow = true {
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

	allow {
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

	allow {
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

	allow {
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
