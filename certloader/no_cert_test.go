/*-
 * Copyright 2019 Square Inc.
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

package certloader

import (
	"crypto/x509"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoCertificate(t *testing.T) {
	cabundle, err := os.CreateTemp("", "ghostunnel-test")
	assert.NoError(t, err, "temp file error")
	defer os.Remove(cabundle.Name())

	_, err = cabundle.Write([]byte(testCertificate))
	assert.NoError(t, err, "temp file error")

	cert, err := NoCertificate(cabundle.Name())
	assert.NoError(t, err, "should read valid bundle")

	id := cert.GetIdentifier()
	assert.Empty(t, id, "no cert should have empty id")

	c, err := cert.GetCertificate(nil)
	assert.NoError(t, err, "should not error on GetCertificate")
	assert.NotNil(t, c, "should have non-nil server cert")

	c, err = cert.GetClientCertificate(nil)
	assert.NoError(t, err, "should not error on GetClientCertificate")
	assert.NotNil(t, c, "should have non-nil client cert")
}

func TestNoCertificateGetTrustStore(t *testing.T) {
	cabundle, err := os.CreateTemp("", "ghostunnel-test")
	assert.NoError(t, err, "temp file error")
	defer os.Remove(cabundle.Name())

	_, err = cabundle.Write([]byte(testCertificate))
	assert.NoError(t, err, "temp file error")

	cert, err := NoCertificate(cabundle.Name())
	assert.NoError(t, err, "should read valid bundle")

	// GetTrustStore should return a pool populated from the CA bundle file.
	pool := cert.GetTrustStore()
	assert.NotNil(t, pool, "GetTrustStore should return non-nil pool after NoCertificate")

	// Sanity-check: the cert in the bundle should be present in the returned pool.
	// We verify this by parsing the bundle's leaf cert and confirming it can be
	// validated against the pool (the cert is self-signed in the test fixture).
	parsed, err := readX509(cabundle.Name())
	assert.NoError(t, err, "should parse test bundle")
	assert.Len(t, parsed, 1, "test bundle should contain one cert")

	_, err = parsed[0].Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: parsed[0].NotBefore.Add(1),
	})
	assert.NoError(t, err, "cert from bundle should verify against the pool returned by GetTrustStore")
}

func TestNoCertificateInvalid(t *testing.T) {
	cabundle, err := os.CreateTemp("", "ghostunnel-test")
	assert.NoError(t, err, "temp file error")
	defer os.Remove(cabundle.Name())

	_, err = cabundle.Write([]byte("invalid"))
	assert.NoError(t, err, "temp file error")

	_, err = NoCertificate(cabundle.Name())
	assert.Error(t, err, "should not read invalid bundle")
}
