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
