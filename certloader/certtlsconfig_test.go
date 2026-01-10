/*-
 * Copyright 2025 Ghostunnel
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
	"io"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mockCertificateNoPrivateKey simulates a certificate without a private key
type mockCertificateNoPrivateKey struct{}

func (m *mockCertificateNoPrivateKey) Reload() error {
	return nil
}

func (m *mockCertificateNoPrivateKey) GetIdentifier() string {
	return "mock-cert-no-key"
}

func (m *mockCertificateNoPrivateKey) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Return a certificate without a private key
	return &tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  nil, // No private key
	}, nil
}

func (m *mockCertificateNoPrivateKey) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  nil,
	}, nil
}

func (m *mockCertificateNoPrivateKey) GetTrustStore() *x509.CertPool {
	return nil
}

// mockCertificateWithPrivateKey simulates a certificate with a private key
type mockCertificateWithPrivateKey struct{}

func (m *mockCertificateWithPrivateKey) Reload() error {
	return nil
}

func (m *mockCertificateWithPrivateKey) GetIdentifier() string {
	return "mock-cert-with-key"
}

func (m *mockCertificateWithPrivateKey) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	// Return a minimal certificate with a non-nil private key placeholder
	// In practice, we just need PrivateKey to be non-nil for CanServe to return true
	return &tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  struct{}{}, // Non-nil placeholder
	}, nil
}

func (m *mockCertificateWithPrivateKey) GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{
		Certificate: [][]byte{},
		PrivateKey:  struct{}{},
	}, nil
}

func (m *mockCertificateWithPrivateKey) GetTrustStore() *x509.CertPool {
	return x509.NewCertPool()
}

func TestCertTLSConfigSourceGetServerConfigCannotServe(t *testing.T) {
	cert := &mockCertificateNoPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	_, err := source.GetServerConfig(nil)
	assert.NotNil(t, err, "should fail when certificate cannot serve (no private key)")
	assert.Contains(t, err.Error(), "cannot be used as a server")
}

func TestCertTLSConfigSourceCanServeWithPrivateKey(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	assert.True(t, source.CanServe(), "should be able to serve with private key")
}

func TestCertTLSConfigSourceCanServeWithoutPrivateKey(t *testing.T) {
	cert := &mockCertificateNoPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	assert.False(t, source.CanServe(), "should not be able to serve without private key")
}

func TestCertTLSConfigSourceGetClientConfig(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	config, err := source.GetClientConfig(nil)
	assert.Nil(t, err, "should succeed getting client config")
	assert.NotNil(t, config, "client config should not be nil")

	tlsConfig := config.GetClientConfig()
	assert.NotNil(t, tlsConfig, "TLS config should not be nil")
}

func TestCertTLSConfigSourceGetServerConfig(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	config, err := source.GetServerConfig(nil)
	assert.Nil(t, err, "should succeed getting server config with private key")
	assert.NotNil(t, config, "server config should not be nil")

	tlsConfig := config.GetServerConfig()
	assert.NotNil(t, tlsConfig, "TLS config should not be nil")
}

func TestNewCertTLSConfigNilBase(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	config := newCertTLSConfig(cert, nil)

	assert.NotNil(t, config.base, "base should be initialized to non-nil config when nil passed")
}

func TestNewCertTLSConfigWithBase(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	base := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	config := newCertTLSConfig(cert, base)

	assert.Equal(t, base, config.base, "base should be set to provided config")
}

func TestCertTLSConfigSourceReload(t *testing.T) {
	cert := &mockCertificateWithPrivateKey{}
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))

	err := source.Reload()
	assert.Nil(t, err, "reload should succeed")
}
