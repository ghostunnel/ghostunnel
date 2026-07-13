//go:build cgo && !nopkcs11

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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sentinelKey stands in for the cached HSM private key handle. Only its pointer
// is copied by the reuse branch; it is never used to sign.
type sentinelKey struct{}

func (sentinelKey) Public() crypto.PublicKey { return nil }

// genSelfSigned writes a self-signed ECDSA certificate to a temp PEM file and
// returns the parsed leaf and the file path. Passing a non-nil key reuses it,
// otherwise a fresh key is generated.
func genSelfSigned(t *testing.T, dir, name string, key *ecdsa.PrivateKey) (*x509.Certificate, string, *ecdsa.PrivateKey) {
	t.Helper()
	if key == nil {
		var err error
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	path := filepath.Join(dir, name+".pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))

	return leaf, path, key
}

// writeCABundle writes a PEM bundle containing the given certificate so the
// positive reload test runs hermetically instead of hitting SystemCertPool.
func writeCABundle(t *testing.T, dir string, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(dir, "ca-bundle.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// TestPKCS11ReloadRejectsKeyMismatch verifies that reloading a certificate whose
// public key no longer matches the cached HSM private key fails closed and keeps
// the previous (self-consistent) certificate.
func TestPKCS11ReloadRejectsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	cachedLeaf, _, _ := genSelfSigned(t, dir, "cached", nil) // key A
	newLeaf, newPath, _ := genSelfSigned(t, dir, "new", nil) // key B (different)

	prior := &tls.Certificate{
		Certificate: [][]byte{cachedLeaf.Raw},
		Leaf:        cachedLeaf,
		PrivateKey:  sentinelKey{},
	}
	c := &pkcs11Certificate{certificatePath: newPath, logger: log.New(os.Stderr, "", 0)}
	c.cachedCertificate.Store(prior)

	err := c.Reload()
	require.Error(t, err, "reload with a mismatched public key must fail closed")
	assert.Same(t, prior, c.cachedCertificate.Load(), "cached certificate must be unchanged")
	assert.NotEqual(t, newLeaf.PublicKey, c.cachedCertificate.Load().Leaf.PublicKey)
}

// TestPKCS11ReloadAcceptsSameKey verifies that a cert-only rotation (a new
// certificate for the same HSM key) is still accepted, so the mismatch check is
// not over-strict.
func TestPKCS11ReloadAcceptsSameKey(t *testing.T) {
	dir := t.TempDir()
	cachedLeaf, _, key := genSelfSigned(t, dir, "cached", nil)   // key A
	newLeaf, newPath, _ := genSelfSigned(t, dir, "renewed", key) // same key A, new cert

	caBundle := writeCABundle(t, dir, newLeaf)

	prior := &tls.Certificate{
		Certificate: [][]byte{cachedLeaf.Raw},
		Leaf:        cachedLeaf,
		PrivateKey:  sentinelKey{},
	}
	c := &pkcs11Certificate{certificatePath: newPath, caBundlePath: caBundle, logger: log.New(os.Stderr, "", 0)}
	c.cachedCertificate.Store(prior)

	err := c.Reload()
	require.NoError(t, err, "reload of a new cert for the same key must succeed")

	loaded := c.cachedCertificate.Load()
	assert.NotSame(t, prior, loaded, "cached certificate must be replaced with the new leaf")
	assert.Equal(t, newLeaf.SerialNumber, loaded.Leaf.SerialNumber, "new leaf must be served")
	assert.Equal(t, prior.PrivateKey, loaded.PrivateKey, "cached HSM private key handle must be reused")
}
