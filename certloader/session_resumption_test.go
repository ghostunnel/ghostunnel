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
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for how session resumption interacts with reloading. Two properties
// are under test:
//
//   - A resumed connection skips VerifyPeerCertificate, and with it the access
//     control decision made during the original full handshake. That is the
//     point of resumption, and it is what keeps resumed connections cheap.
//   - A reload rebuilds the server config, which mints new session ticket keys
//     and so drops outstanding tickets. Clients fall back to a full handshake,
//     where they are verified against the current roots, served the current
//     certificate, and run through access control again.

// resumptionFixture is a running TLS server backed by a reloadable
// certificate, plus a client config that retains session tickets.
type resumptionFixture struct {
	cert     Certificate
	config   TLSServerConfig
	listener net.Listener
	client   *tls.Config
	// verifyCalls counts VerifyPeerCertificate invocations on the server,
	// standing in for the access control callback ghostunnel installs there.
	verifyCalls atomic.Int32
}

func newResumptionFixture(t *testing.T) *resumptionFixture {
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
		ClientAuth: tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(_ [][]byte, _ [][]*x509.Certificate) error {
			f.verifyCalls.Add(1)
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

// A resumed connection reuses the access control decision from the original
// full handshake: crypto/tls does not call VerifyPeerCertificate on resumption.
// This pins the performance property that the reload behavior below relies on.
func TestResumedConnectionSkipsVerifyPeerCertificate(t *testing.T) {
	f := newResumptionFixture(t)

	resumed, err := f.dial(t)
	require.NoError(t, err, "initial handshake should succeed")
	assert.False(t, resumed, "first connection cannot resume")
	assert.EqualValues(t, 1, f.verifyCalls.Load(), "full handshake runs VerifyPeerCertificate")

	resumed, err = f.dial(t)
	require.NoError(t, err, "second handshake should succeed")
	require.True(t, resumed, "second connection should resume (the test is meaningless otherwise)")
	assert.EqualValues(t, 1, f.verifyCalls.Load(), "resumed connection must not run VerifyPeerCertificate")
}

// A reload rebuilds the server config, which mints fresh session ticket keys,
// so outstanding tickets stop decrypting. That is what guarantees a reload
// reaches clients that would otherwise resume: they fall back to a full
// handshake, where the current certificate is presented, the current roots
// are used to verify them, and access control runs again.
func TestReloadDropsSessions(t *testing.T) {
	f := newResumptionFixture(t)

	_, err := f.dial(t)
	require.NoError(t, err)

	resumed, err := f.dial(t)
	require.NoError(t, err)
	require.True(t, resumed, "session should resume before the reload")
	require.EqualValues(t, 1, f.verifyCalls.Load())

	// Nothing on disk has changed: a reload still has to drop the session, or a
	// client holding a ticket could keep using configuration we replaced.
	before := f.config.GetServerConfig()
	require.NoError(t, f.cert.Reload())
	assert.NotSame(t, before, f.config.GetServerConfig(),
		"a reload must rebuild the server config")

	resumed, err = f.dial(t)
	require.NoError(t, err, "client should still be able to connect after a reload")
	assert.False(t, resumed, "session ticket must not survive a reload")
	assert.EqualValues(t, 2, f.verifyCalls.Load(),
		"the full handshake after a reload must run VerifyPeerCertificate again")
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
