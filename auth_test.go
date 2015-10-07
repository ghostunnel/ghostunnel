package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
)

var fakeConn = tls.ConnectionState{
	VerifiedChains: [][]*x509.Certificate{
		[]*x509.Certificate{
			&x509.Certificate{
				Subject: pkix.Name{
					CommonName:         "gopher",
					OrganizationalUnit: []string{"triangle", "circle"},
				},
			},
		},
	},
}

func TestAuthorizeNotVerified(t *testing.T) {
	*allowAll = true
	*allowedCNs = []string{}
	*allowedOUs = []string{}

	assert.False(t, authorized(tls.ConnectionState{}), "conn w/o cert should be rejected")
}

func TestAuthorizeReject(t *testing.T) {
	*allowAll = false
	*allowedCNs = []string{"test"}
	*allowedOUs = []string{"test"}

	assert.False(t, authorized(fakeConn), "should reject cert w/o matching CN/OU")
}

func TestAuthorizeAllowAll(t *testing.T) {
	*allowAll = true
	*allowedCNs = []string{}
	*allowedOUs = []string{}

	assert.True(t, authorized(fakeConn), "allow-all should always allow authed clients")
}

func TestAuthorizeAllowCN(t *testing.T) {
	*allowAll = false
	*allowedCNs = []string{"gopher"}
	*allowedOUs = []string{}

	assert.True(t, authorized(fakeConn), "allow-cn should allow clients with matching CN")
}

func TestAuthorizeAllowOU(t *testing.T) {
	*allowAll = false
	*allowedCNs = []string{}
	*allowedOUs = []string{"circle"}

	assert.True(t, authorized(fakeConn), "allow-cn should allow clients with matching CN")
}
