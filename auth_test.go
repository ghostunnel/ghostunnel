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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

var fakeConnectionState = tls.ConnectionState{
	VerifiedChains: [][]*x509.Certificate{
		{
			{
				Subject: pkix.Name{
					CommonName:         "gopher",
					OrganizationalUnit: []string{"triangle", "circle"},
				},
				DNSNames:    []string{"circle"},
				IPAddresses: []net.IP{net.IPv4(192, 168, 99, 100)},
			},
		},
	},
}

func TestAuthorizeNotVerified(t *testing.T) {
	*serverAllowAll = true
	*serverAllowedCNs = []string{}
	*serverAllowedOUs = []string{}
	*serverAllowedDNSs = []string{}
	*serverAllowedIPs = []net.IP{}

	assert.False(t, authorized(tls.ConnectionState{}), "conn w/o cert should be rejected")
}

func TestAuthorizeReject(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = []string{"test"}
	*serverAllowedOUs = []string{"test"}
	*serverAllowedDNSs = []string{"test"}
	*serverAllowedIPs = []net.IP{}

	assert.False(t, authorized(fakeConnectionState), "should reject cert w/o matching CN/OU")
}

func TestAuthorizeAllowAll(t *testing.T) {
	*serverAllowAll = true
	*serverAllowedCNs = []string{}
	*serverAllowedOUs = []string{}
	*serverAllowedDNSs = []string{}
	*serverAllowedIPs = []net.IP{}

	assert.True(t, authorized(fakeConnectionState), "allow-all should always allow authed clients")
}

func TestAuthorizeAllowCN(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = []string{"gopher"}
	*serverAllowedOUs = []string{}
	*serverAllowedDNSs = []string{}
	*serverAllowedIPs = []net.IP{}

	assert.True(t, authorized(fakeConnectionState), "allow-cn should allow clients with matching CN")
}

func TestAuthorizeAllowOU(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = []string{}
	*serverAllowedOUs = []string{"circle"}
	*serverAllowedDNSs = []string{}
	*serverAllowedIPs = []net.IP{}

	assert.True(t, authorized(fakeConnectionState), "allow-ou should allow clients with matching OU")
}

func TestAuthorizeAllowDNS(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = []string{}
	*serverAllowedOUs = []string{}
	*serverAllowedDNSs = []string{"circle"}
	*serverAllowedIPs = []net.IP{}

	assert.True(t, authorized(fakeConnectionState), "allow-dns-san should allow clients with matching DNS SAN")
}

func TestAuthorizeAllowIP(t *testing.T) {
	*serverAllowAll = false
	*serverAllowedCNs = []string{}
	*serverAllowedOUs = []string{}
	*serverAllowedDNSs = []string{}
	*serverAllowedIPs = []net.IP{net.IPv4(192, 168, 99, 100)}

	assert.True(t, authorized(fakeConnectionState), "allow-ip-san should allow clients with matching IP SAN")
}
