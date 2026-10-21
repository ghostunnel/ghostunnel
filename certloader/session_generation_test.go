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
	"crypto/tls"
	"crypto/x509"
	"net"
	"sync/atomic"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for BindSessionsToGeneration, over real loopback TLS. The fixture and
// the helpers it uses live in session_resumption_test.go.
//
// Every test that involves a handshake runs against both TLS 1.2, which
// resumes from a ticket delivered during the handshake, and TLS 1.3, which
// resumes from a pre-shared key out of a ticket delivered afterwards. The two
// take different paths through crypto/tls, and the wrapper has to cover both.

var tlsVersions = []struct {
	name    string
	version uint16
}{
	{"TLS1.2", tls.VersionTLS12},
	{"TLS1.3", tls.VersionTLS13},
}

// newGenerationFixture returns a fixture whose listener serves a config bound
// to gen.
func newGenerationFixture(t *testing.T, gen *SessionGeneration, version uint16) *resumptionFixture {
	t.Helper()

	return newResumptionFixture(t, resumptionOptions{
		version: version,
		wrap: func(inner TLSServerConfig) TLSServerConfig {
			return BindSessionsToGeneration(inner, gen)
		},
	})
}

// Within one generation the wrapper changes nothing that matters: clients
// resume, and a resumed connection still skips VerifyPeerCertificate. That is
// the performance property resumption exists for, and binding sessions to a
// generation must not cost it.
func TestSessionGenerationResumesWithinGeneration(t *testing.T) {
	for _, v := range tlsVersions {
		t.Run(v.name, func(t *testing.T) {
			gen := &SessionGeneration{}
			f := newGenerationFixture(t, gen, v.version)

			resumed, err := f.dial(t)
			require.NoError(t, err, "initial handshake should succeed")
			require.False(t, resumed, "first connection cannot resume")
			require.EqualValues(t, 1, f.verifyCalls.Load(), "full handshake runs VerifyPeerCertificate")

			resumed, err = f.dial(t)
			require.NoError(t, err, "second handshake should succeed")
			assert.True(t, resumed, "second connection should resume within the generation")
			assert.EqualValues(t, 1, f.verifyCalls.Load(), "resumed connection must not run VerifyPeerCertificate")
		})
	}
}

// Advancing the generation invalidates outstanding sessions: the client's next
// connection is a full handshake, which runs access control again.
func TestSessionGenerationInvalidatesOnAdvance(t *testing.T) {
	for _, v := range tlsVersions {
		t.Run(v.name, func(t *testing.T) {
			gen := &SessionGeneration{}
			f := newGenerationFixture(t, gen, v.version)

			_, err := f.dial(t)
			require.NoError(t, err)
			resumed, err := f.dial(t)
			require.NoError(t, err)
			require.True(t, resumed, "session should resume before the generation advances")

			gen.Advance()

			resumed, err = f.dial(t)
			require.NoError(t, err, "client should still be able to connect")
			assert.False(t, resumed, "session must not survive an advance")
			assert.EqualValues(t, 2, f.verifyCalls.Load(),
				"the full handshake after an advance must run VerifyPeerCertificate again")
		})
	}
}

// ticketRecorder is a ClientSessionCache that keeps the raw ticket the server
// issued, so a test can hand it back to a server config directly.
type ticketRecorder struct {
	tls.ClientSessionCache
	last atomic.Pointer[[]byte]
}

func (r *ticketRecorder) Put(key string, cs *tls.ClientSessionState) {
	if cs != nil {
		if ticket, _, err := cs.ResumptionState(); err == nil {
			r.last.Store(&ticket)
		}
	}
	r.ClientSessionCache.Put(key, cs)
}

// A fresh clone per generation gets its own automatic session ticket keys, but
// correctness must not rest on that: Config.Clone copies ticket keys from its
// source, so a config that has served a handshake of its own would hand the
// same keys to every later clone. With one set of keys configured explicitly,
// so that both generations share them, the generation tag alone has to force a
// full handshake.
func TestSessionGenerationRejectsOtherGenerationWithSharedKeys(t *testing.T) {
	for _, v := range tlsVersions {
		t.Run(v.name, func(t *testing.T) {
			gen := &SessionGeneration{}
			f := newResumptionFixture(t, resumptionOptions{
				version:           v.version,
				sessionTicketKeys: [][32]byte{{'g', 'h', 'o', 's', 't'}},
				wrap: func(inner TLSServerConfig) TLSServerConfig {
					return BindSessionsToGeneration(inner, gen)
				},
			})

			recorder := &ticketRecorder{ClientSessionCache: f.client.ClientSessionCache}
			f.client.ClientSessionCache = recorder

			_, err := f.dial(t)
			require.NoError(t, err)
			resumed, err := f.dial(t)
			require.NoError(t, err)
			require.True(t, resumed, "session should resume before the generation advances")

			ticket := recorder.last.Load()
			require.NotNil(t, ticket, "expected to capture a session ticket")
			previous := f.config.GetServerConfig()

			gen.Advance()

			current := f.config.GetServerConfig()
			require.NotSame(t, previous, current, "an advance must rebuild the config")

			// The keys really are shared, so the ticket still decrypts under the
			// new generation's config: the only thing refusing it is the tag.
			state, err := current.DecryptTicket(*ticket, tls.ConnectionState{})
			require.NoError(t, err)
			require.NotNil(t, state, "both generations must share ticket keys for this test to mean anything")

			state, err = current.UnwrapSession(*ticket, tls.ConnectionState{})
			require.NoError(t, err, "a ticket from another generation is refused, not an error")
			assert.Nil(t, state, "a ticket from another generation must not yield a session")

			resumed, err = f.dial(t)
			require.NoError(t, err)
			assert.False(t, resumed, "session must not survive an advance, even with shared ticket keys")
		})
	}
}

// The wrapper clones once per generation, not once per connection: repeated
// calls hand out the same config, and a new one appears only when the
// generation advances or the config underneath it is rebuilt (as a trust store
// reload does).
func TestSessionGenerationConfigStableWithinGeneration(t *testing.T) {
	gen := &SessionGeneration{}
	f := newGenerationFixture(t, gen, 0)

	first := f.config.GetServerConfig()
	require.Same(t, first, f.config.GetServerConfig(), "config must be stable within a generation")

	gen.Advance()

	second := f.config.GetServerConfig()
	require.NotSame(t, first, second, "an advance must rebuild the config")
	require.Same(t, second, f.config.GetServerConfig(), "config must be stable within a generation")

	require.NoError(t, f.cert.Reload())

	third := f.config.GetServerConfig()
	assert.NotSame(t, second, third, "a rebuilt inner config must be picked up")
}

// The point of all this: an access decision that changes is not visible to a
// client that resumes, and advancing the generation is what makes it visible.
func TestSessionGenerationDenyAfterAdvance(t *testing.T) {
	for _, v := range tlsVersions {
		t.Run(v.name, func(t *testing.T) {
			gen := &SessionGeneration{}
			f := newGenerationFixture(t, gen, v.version)

			_, err := f.dial(t)
			require.NoError(t, err)

			// Access is revoked, but a resumed connection never asks again.
			f.deny.Store(true)

			resumed, err := f.dial(t)
			require.NoError(t, err, "a resumed connection does not re-run access control")
			require.True(t, resumed, "session should resume before the generation advances")

			gen.Advance()

			_, err = f.dial(t)
			assert.Error(t, err, "after an advance the client must be re-evaluated, and rejected")
		})
	}
}

// The ACME source serves TLS-ALPN-01 challenge handshakes through a
// GetConfigForClient hook that clones the config it was built with and disables
// session tickets on the clone. Wrapping must leave that hook in place, so
// validator probes keep working and still get no ticket.
func TestSessionGenerationPreservesACMEChallengeHook(t *testing.T) {
	magicConfig := certmagic.NewDefault()
	source := &acmeTLSConfigSource{
		magicConfig:  magicConfig,
		gtACMEConfig: &ACMEConfig{},
	}
	inner := &acmeTLSConfig{
		magicConfig: magicConfig,
		base:        &tls.Config{MinVersion: tls.VersionTLS12},
		source:      source,
	}

	config := BindSessionsToGeneration(inner, &SessionGeneration{}).GetServerConfig()
	require.NotNil(t, config.WrapSession, "the wrapper must install its session hooks")
	require.NotNil(t, config.UnwrapSession, "the wrapper must install its session hooks")
	require.NotNil(t, config.GetConfigForClient, "the challenge cert handler must survive wrapping")

	relaxed, err := config.GetConfigForClient(&tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{acmez.ACMETLS1Protocol},
	})
	require.NoError(t, err)
	require.NotNil(t, relaxed, "a validator-shaped ClientHello must get the relaxed config")
	assert.True(t, relaxed.SessionTicketsDisabled, "a challenge handshake must not issue a ticket")
	assert.Equal(t, tls.NoClientCert, relaxed.ClientAuth)

	normal, err := config.GetConfigForClient(&tls.ClientHelloInfo{
		ServerName:      "example.com",
		SupportedProtos: []string{"h2"},
	})
	require.NoError(t, err)
	assert.Nil(t, normal, "a normal ClientHello must fall through to the wrapped config")
}

// reloadingServerConfig hands out its current config and then reloads, the
// way Environment.reload in signals.go does: swap the config, then advance the
// generation. It simulates a reload landing in the middle of
// generationBoundTLSConfig.GetServerConfig.
type reloadingServerConfig struct {
	gen      *SessionGeneration
	current  atomic.Pointer[tls.Config]
	next     *tls.Config
	reloaded atomic.Bool
}

func (r *reloadingServerConfig) GetServerConfig() *tls.Config {
	config := r.current.Load()
	if r.reloaded.CompareAndSwap(false, true) {
		r.current.Store(r.next)
		r.gen.Advance()
	}
	return config
}

// A reload that lands while the wrapper is building a config must not pair
// the old config with the new generation: a handshake on that config would
// mint a ticket that stays resumable after the reload, even though it was
// issued under configuration the reload replaced. Ticket keys are shared, so
// only the generation tag stands in the way.
func TestSessionGenerationReloadDuringGetServerConfig(t *testing.T) {
	ca := newTestCA(t, "Reload Race Test CA")
	certPEM, keyPEM := ca.issue(t, "server", x509.ExtKeyUsageServerAuth)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	newConfig := func() *tls.Config {
		config := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		}
		config.SetSessionTicketKeys([][32]byte{{'g', 'h', 'o', 's', 't'}})
		return config
	}

	gen := &SessionGeneration{}
	inner := &reloadingServerConfig{gen: gen, next: newConfig()}
	inner.current.Store(newConfig())
	wrapped := BindSessionsToGeneration(inner, gen)

	// The reload happens during this call.
	racing := wrapped.GetServerConfig()
	require.EqualValues(t, 1, gen.Current(), "the reload should have advanced the generation")

	// Complete a handshake on the config handed out during the reload and keep
	// the ticket it issues. TLS 1.2 delivers the ticket during the handshake.
	recorder := &ticketRecorder{ClientSessionCache: tls.NewLRUClientSessionCache(1)}
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- tls.Server(serverConn, racing).Handshake() }()
	client := tls.Client(clientConn, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		ServerName:         "localhost",
		ClientSessionCache: recorder,
	})
	require.NoError(t, client.Handshake())
	require.NoError(t, <-serverErr)
	ticket := recorder.last.Load()
	require.NotNil(t, ticket, "expected to capture a session ticket")

	// Once the reload is over, that ticket must not resume.
	current := wrapped.GetServerConfig()
	state, err := current.UnwrapSession(*ticket, tls.ConnectionState{})
	require.NoError(t, err)
	assert.Nil(t, state, "a ticket issued during a reload must not resume after it")
}
