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
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"sync/atomic"
)

// SessionGeneration counts reloads. A server-side TLS session created in one
// generation cannot be resumed in another, see BindSessionsToGeneration.
//
// This is what bounds how long a resumed connection may keep reusing the access
// control decision from its original full handshake: crypto/tls does not call
// VerifyPeerCertificate on a resumed connection, so without a bound a client
// holding a ticket could keep using a decision made against configuration that
// has since been replaced. Tying invalidation to the reload rather than to a
// change in the underlying configuration means it does not matter whether the
// reload changed anything, or even whether it succeeded.
//
// It is safe to use concurrently, and the zero value is ready to use.
type SessionGeneration struct {
	n atomic.Uint64
}

// Advance moves to the next generation, invalidating all sessions created in
// the previous one.
func (g *SessionGeneration) Advance() {
	g.n.Add(1)
}

// Current returns the generation new sessions are being created in.
func (g *SessionGeneration) Current() uint64 {
	return g.n.Load()
}

// sessionGenerationPrefix identifies ghostunnel's entry in
// tls.SessionState.Extra. crypto/tls requires entries there to be append-only
// and recognizable on their own, so that several layers of a protocol stack can
// share the field. The trailing version byte leaves room to change the encoding
// that follows it without a ticket from an older ghostunnel being mistaken for
// one of our own.
var sessionGenerationPrefix = []byte("ghostunnel/session-generation\x00\x01")

// sessionGenerationTag returns the tag identifying sessions created in the
// given generation.
func sessionGenerationTag(generation uint64) []byte {
	tag := make([]byte, 0, len(sessionGenerationPrefix)+8)
	tag = append(tag, sessionGenerationPrefix...)
	return binary.BigEndian.AppendUint64(tag, generation)
}

// hasSessionGenerationTag reports whether the session carries the given tag.
func hasSessionGenerationTag(state *tls.SessionState, tag []byte) bool {
	for _, extra := range state.Extra {
		if bytes.Equal(extra, tag) {
			return true
		}
	}
	return false
}

// BindSessionsToGeneration wraps a TLSServerConfig so that a session can only
// be resumed in the generation that created it. Once gen advances, clients
// holding a ticket fall back to a full handshake, which presents the current
// certificate, verifies against the current trust store, and runs access
// control again.
//
// The wrapper assumes the inner config returns the same *tls.Config pointer
// until something about it changes, as certTLSConfig, acmeTLSConfig and
// spiffeTLSConfig all do: it uses that pointer, together with the generation,
// as its cache key so the hot path stays a pointer comparison rather than a
// clone per connection.
//
// Do not clone the configs it returns. The session hooks installed on them
// encrypt and decrypt tickets with the ticket keys of the config they were
// built for, so a clone would keep minting tickets for the generation it was
// cloned from.
func BindSessionsToGeneration(inner TLSServerConfig, gen *SessionGeneration) TLSServerConfig {
	return &generationBoundTLSConfig{inner: inner, gen: gen}
}

type generationBoundTLSConfig struct {
	inner TLSServerConfig
	gen   *SessionGeneration

	// Cached config, keyed on the inner config pointer and the generation it
	// was built for. Two callers racing a change may each build once, which is
	// harmless; certTLSConfig accepts the same trade-off.
	cached atomic.Pointer[generationBoundConfig]
}

// generationBoundConfig pairs a built *tls.Config with the inner config and
// generation it was built from. The three are published together through a
// single atomic.Pointer, so a reader never sees a config paired with a stale
// cache key.
type generationBoundConfig struct {
	inner      *tls.Config
	generation uint64
	config     *tls.Config
}

func (c *generationBoundTLSConfig) GetServerConfig() *tls.Config {
	inner := c.inner.GetServerConfig()
	generation := c.gen.Current()
	if cached := c.cached.Load(); cached != nil && cached.inner == inner && cached.generation == generation {
		return cached.config
	}
	config := bindSessionsToGeneration(inner, generation)
	c.cached.Store(&generationBoundConfig{inner: inner, generation: generation, config: config})
	return config
}

// bindSessionsToGeneration returns a clone of config whose session tickets are
// tagged with, and only accepted in, the given generation.
//
// There are two mechanisms at work here, on purpose. The clone gets its own set
// of automatic session ticket keys (Go rotates them every 24h and keeps them
// for 7 days), so tickets from another generation do not decrypt to begin with.
// The explicit tag means correctness does not rest on that: Clone copies ticket
// keys from its source, so should the inner config ever serve a handshake of
// its own and populate keys that every later clone inherits, the tag still
// forces a full handshake.
//
// The generation is captured here, when the clone is built, rather than read
// when a ticket is wrapped. A handshake that straddles a reload therefore
// cannot mint a ticket for the new generation out of a decision made under the
// old one.
func bindSessionsToGeneration(inner *tls.Config, generation uint64) *tls.Config {
	config := inner.Clone()
	tag := sessionGenerationTag(generation)

	config.WrapSession = func(cs tls.ConnectionState, ss *tls.SessionState) ([]byte, error) {
		ss.Extra = append(ss.Extra, tag)
		return config.EncryptTicket(cs, ss)
	}

	config.UnwrapSession = func(identity []byte, cs tls.ConnectionState) (*tls.SessionState, error) {
		state, err := config.DecryptTicket(identity, cs)
		if err != nil || state == nil {
			return nil, err
		}
		if !hasSessionGenerationTag(state, tag) {
			// A session from another generation. Returning no session (rather
			// than an error) makes crypto/tls fall back to a full handshake
			// instead of failing the connection.
			return nil, nil
		}
		return state, nil
	}

	return config
}
