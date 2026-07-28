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

package certloader

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for how session resumption interacts with reloading. Two properties are
// under test, and they cover different kinds of change:
//
//   - Authorization is re-checked on every connection, resumed or not, because
//     it runs as VerifyConnection. This is what catches a changed ACL or OPA
//     policy, neither of which touches the TLS configuration at all.
//   - A reload rebuilds the server config, which mints new session ticket keys
//     and so drops outstanding tickets. Clients fall back to a full handshake,
//     where they are verified against the current roots and served the current
//     certificate.

// errDenied stands in for an authorization failure from the callback layered
// on top of the TLS config (in ghostunnel, an auth.ACL verdict).
var errDenied = errors.New("unauthorized: denied by test")

// observedState records what the server's access control callback was handed,
// so a test can assert on connections it does not otherwise get to inspect.
type observedState struct {
	didResume        bool
	peerCertificates int
	verifiedChains   int
}

// resumptionFixture is a running TLS server backed by a reloadable
// certificate, plus a client config that retains session tickets.
type resumptionFixture struct {
	cert     Certificate
	config   TLSServerConfig
	listener net.Listener
	client   *tls.Config
	// denied is consulted by the server's base VerifyConnection callback,
	// standing in for an ACL or OPA policy that changed under a running server.
	denied atomic.Bool

	mu       sync.Mutex
	observed []observedState
}

// states returns what the access control callback saw, in connection order.
func (f *resumptionFixture) states() []observedState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]observedState(nil), f.observed...)
}

func newResumptionFixture(t *testing.T) *resumptionFixture {
	t.Helper()
	return newResumptionFixtureWithClientAuth(t, tls.RequireAndVerifyClientCert)
}

// newResumptionFixtureWithClientAuth builds the fixture with a specific
// ClientAuth, so tests can exercise both the chain-verifying mode and the
// RequireAnyClientCert mode that SPKI pinning runs under.
func newResumptionFixtureWithClientAuth(t *testing.T, clientAuth tls.ClientAuthType) *resumptionFixture {
	t.Helper()

	dir := t.TempDir()
	ca := newTestCA(t, "Resumption Test CA")
	serverCertPath := filepath.Join(dir, "server-cert.pem")
	serverKeyPath := filepath.Join(dir, "server-key.pem")
	caBundlePath := filepath.Join(dir, "ca-bundle.pem")

	serverCert, serverKey := ca.issue(t, "server", x509.ExtKeyUsageServerAuth)
	require.NoError(t, os.WriteFile(serverCertPath, serverCert, 0600))
	require.NoError(t, os.WriteFile(serverKeyPath, serverKey, 0600))
	require.NoError(t, os.WriteFile(caBundlePath, ca.certPEM, 0600))

	cert, err := CertificateFromPEMFiles(serverCertPath, serverKeyPath, caBundlePath)
	require.NoError(t, err)

	f := &resumptionFixture{cert: cert}

	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: clientAuth,
		VerifyConnection: func(state tls.ConnectionState) error {
			f.mu.Lock()
			f.observed = append(f.observed, observedState{
				didResume:        state.DidResume,
				peerCertificates: len(state.PeerCertificates),
				verifiedChains:   len(state.VerifiedChains),
			})
			f.mu.Unlock()
			if f.denied.Load() {
				return errDenied
			}
			return nil
		},
	}

	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))
	f.config, err = source.GetServerConfig(base)
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	f.listener = NewListener(listener, f.config)
	t.Cleanup(func() { _ = f.listener.Close() })

	go func() {
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				return
			}
			// A TLS 1.3 ticket is only delivered after the handshake, so the
			// client has to read something before it can resume. Give it a
			// byte to read.
			go func() {
				defer conn.Close()
				_, _ = conn.Write([]byte("x"))
			}()
		}
	}()

	clientCertPEM, clientKeyPEM := ca.issue(t, "client", x509.ExtKeyUsageClientAuth)
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	require.NoError(t, err)

	f.client = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{clientCert},
		// The client side of this test is not what's under test; skip
		// verification of the server rather than wiring up a second trust path.
		InsecureSkipVerify: true,
		ClientSessionCache: tls.NewLRUClientSessionCache(8),
	}

	return f
}

// dial completes a handshake and reports whether the session was resumed. It
// reads a byte first so that a TLS 1.3 ticket lands in the session cache.
func (f *resumptionFixture) dial(t *testing.T) (bool, error) {
	t.Helper()

	conn, err := tls.Dial("tcp", f.listener.Addr().String(), f.client)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	if _, err := conn.Read(make([]byte, 1)); err != nil {
		return false, err
	}
	return conn.ConnectionState().DidResume, nil
}

// A resumed connection must still run the authorization callback, so a change
// that only affects authorization (an ACL edit, an OPA policy reload) takes
// effect even for clients holding a session ticket. Nothing about the TLS
// configuration changes here, which is exactly why flushing session tickets on
// reload could never have covered this case.
func TestResumedConnectionIsReauthorized(t *testing.T) {
	f := newResumptionFixture(t)

	resumed, err := f.dial(t)
	require.NoError(t, err, "initial handshake should succeed")
	assert.False(t, resumed, "first connection cannot resume")

	resumed, err = f.dial(t)
	require.NoError(t, err, "second handshake should succeed")
	require.True(t, resumed, "second connection should resume (the test is meaningless otherwise)")

	f.denied.Store(true)

	_, err = f.dial(t)
	require.Error(t, err, "resumed connection must be rejected once authorization changes")
}

// A reload rebuilds the server config, which mints fresh session ticket keys,
// so outstanding tickets stop decrypting. That is what guarantees a reload
// reaches clients that would otherwise resume: they fall back to a full
// handshake, where the current certificate is presented and the current roots
// are used to verify them.
func TestReloadDropsSessions(t *testing.T) {
	f := newResumptionFixture(t)

	_, err := f.dial(t)
	require.NoError(t, err)

	resumed, err := f.dial(t)
	require.NoError(t, err)
	require.True(t, resumed, "session should resume before the reload")

	// Nothing on disk has changed: a reload still has to drop the session, or a
	// client holding a ticket could keep using configuration we replaced.
	before := f.config.GetServerConfig()
	require.NoError(t, f.cert.Reload())
	assert.NotSame(t, before, f.config.GetServerConfig(),
		"a reload must rebuild the server config")

	resumed, err = f.dial(t)
	require.NoError(t, err, "client should still be able to connect after a reload")
	assert.False(t, resumed, "session ticket must not survive a reload")
}

// SPKI pin mode runs under RequireAnyClientCert, so crypto/tls verifies no
// chain and auth.ACL authenticates the peer from the leaf in
// ConnectionState.PeerCertificates alone. That has to hold on resumed
// connections too, where the certificates come out of the session ticket
// rather than off the wire -- otherwise pin checks would silently stop
// running for any client holding a ticket.
func TestResumedPinnedConnectionCarriesPeerCertificate(t *testing.T) {
	f := newResumptionFixtureWithClientAuth(t, tls.RequireAnyClientCert)

	_, err := f.dial(t)
	require.NoError(t, err, "initial handshake should succeed")

	resumed, err := f.dial(t)
	require.NoError(t, err, "second handshake should succeed")
	require.True(t, resumed, "second connection should resume (the test is meaningless otherwise)")

	states := f.states()
	require.Len(t, states, 2, "the callback must run on both connections")
	assert.False(t, states[0].didResume)
	assert.True(t, states[1].didResume, "the second connection must be the resumed one")
	for i, state := range states {
		assert.NotZero(t, state.peerCertificates,
			"connection %d: pin verification needs the peer's leaf certificate", i)
		assert.Zero(t, state.verifiedChains,
			"connection %d: RequireAnyClientCert must not produce verified chains", i)
	}
}

// testCA is a self-signed CA that can issue leaf certificates.
type testCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return &testCA{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// issue returns a PEM-encoded leaf certificate and key signed by the CA.
func (ca *testCA) issue(t *testing.T, commonName string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}
