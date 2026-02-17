//go:build cgo

/*-
 * Copyright 2018 Square Inc.
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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestInvalidPKCS11Module(t *testing.T) {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	_, err := CertificateFromPKCS11Module("", "", "", "", "", logger)
	assert.NotNil(t, err, "should not load invalid PKCS11 certificate/key")
}

func TestPKCS11GetTrustStore(t *testing.T) {
	pool := x509.NewCertPool()
	pool.AddCert(&x509.Certificate{
		Subject: pkix.Name{
			CommonName: "test-ca",
		},
	})

	p11cert := &pkcs11Certificate{
		cachedCertPool: unsafe.Pointer(pool),
	}

	result := p11cert.GetTrustStore()
	assert.NotNil(t, result, "GetTrustStore should return the cached cert pool")
	assert.Equal(t, pool, result, "GetTrustStore should return the same cert pool")
}

func TestGetCachedCertificatePKCS11(t *testing.T) {
	tlscert := &tls.Certificate{
		Leaf: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "test",
			},
		},
	}
	p11cert := &pkcs11Certificate{
		cachedCertificate: unsafe.Pointer(tlscert),
	}

	id := p11cert.GetIdentifier()
	assert.Equal(t, id, "CN=test", "cert should not have empty id")

	c, err := p11cert.GetCertificate(nil)
	assert.Nil(t, err, "should be able to read certificate")
	assert.Equal(t, tlscert, c)

	c, err = p11cert.GetClientCertificate(nil)
	assert.Nil(t, err, "should be able to read certificate")
	assert.Equal(t, tlscert, c)
}
