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
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync/atomic"
	"time"

	spiffeConfig "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	spiffeApi "github.com/spiffe/go-spiffe/v2/workloadapi"
)

type spiffeTLSConfigSource struct {
	client            *spiffeApi.Client
	clientDisableAuth bool
	initTimeout       time.Duration
	logger            *log.Logger
}

// TLSConfigSourceFromWorkloadAPI creates a TLSConfigSource that uses the SPIFFE Workload API.
// initTimeout bounds how long the first certificate fetch (NewX509Source) may block at startup.
// A value of 0 (or negative) means wait indefinitely — the old behavior before the timeout was introduced.
func TLSConfigSourceFromWorkloadAPI(addr string, clientDisableAuth bool, initTimeout time.Duration, logger *log.Logger) (TLSConfigSource, error) {
	client, err := spiffeApi.New(
		context.Background(),
		spiffeApi.WithAddr(addr),
		spiffeApi.WithLogger(spiffeLogger{log: logger}),
	)
	if err != nil {
		return nil, err
	}
	return &spiffeTLSConfigSource{
		client:            client,
		clientDisableAuth: clientDisableAuth,
		initTimeout:       initTimeout,
		logger:            logger,
	}, nil
}

func (s *spiffeTLSConfigSource) Reload() error {
	// The config returned by the workload API maintains itself. Nothing to do here.
	return nil
}

func (s *spiffeTLSConfigSource) CanServe() bool {
	return true
}

func (s *spiffeTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) Close() error {
	return s.client.Close()
}

func (s *spiffeTLSConfigSource) newConfig(base *tls.Config) (*spiffeTLSConfig, error) {
	// NewX509Source blocks until the first update is received from the Workload
	// API. Bound that wait so an unreachable agent surfaces as an error instead
	// of hanging forever. initTimeout <= 0 means wait indefinitely (no deadline).
	ctx := context.Background()
	if s.initTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.initTimeout)
		defer cancel()
	}
	source, err := spiffeApi.NewX509Source(ctx, spiffeApi.WithClient(s.client))
	if err != nil {
		return nil, fmt.Errorf("unable to obtain initial SPIFFE Workload API update (is the agent reachable and is there a registration entry?): %w", err)
	}

	return &spiffeTLSConfig{
		base:              base,
		source:            source,
		clientDisableAuth: s.clientDisableAuth,
	}, nil
}

type spiffeTLSConfig struct {
	base              *tls.Config
	source            *spiffeApi.X509Source
	clientDisableAuth bool

	// Cached configs. SPIFFE has no reloadable trust store (the X509Source
	// maintains itself via the Workload API and certificates are served through
	// a callback), so the built config never changes: build once, cache forever.
	//
	// Nothing in the built config goes stale when the Workload API pushes an
	// update. No pool is baked into it (RootCAs/ClientCAs stay nil): the
	// certificate is served through a callback, and the peer is verified
	// against the trust bundle read from the source at verification time, on
	// every connection (see verifyConnection). Unlike the certificate- and
	// ACME-backed sources, this config is therefore never rebuilt. Outstanding
	// session tickets survive a bundle rotation, but a peer resuming with one
	// is re-verified against the rotated bundle all the same.
	cachedClient atomic.Pointer[tls.Config]
	cachedServer atomic.Pointer[tls.Config]
}

// verifyConnection returns a VerifyConnection callback that authenticates the
// peer's X509-SVID against the current trust bundle, then hands off to the
// base callback (if any) with the resulting chains in place.
//
// This is installed as VerifyConnection rather than VerifyPeerCertificate so
// that it runs on resumed connections too. crypto/tls skips
// VerifyPeerCertificate when a session is resumed, which would leave both the
// SVID verification and the access control layered on top of us unenforced
// there: the trust bundle can rotate, and an ACL or an OPA policy can change,
// while a peer's session ticket is outstanding, and that peer must be held to
// the current ones.
//
// A resumed connection is verified like any other. crypto/tls restores the
// peer's certificates from the session, so verifying them against the bundle
// works the same as on a full handshake, and a bundle rotation takes effect
// for every connection at once, resumed or not.
func (c *spiffeTLSConfig) verifyConnection(base func(tls.ConnectionState) error) func(tls.ConnectionState) error {
	authorizer := spiffeConfig.AuthorizeAny()
	return func(state tls.ConnectionState) error {
		id, chains, err := x509svid.Verify(state.PeerCertificates, c.source)
		if err != nil {
			return err
		}
		if err := authorizer(id, chains); err != nil {
			return err
		}
		if base == nil {
			return nil
		}
		// The Go TLS stack verified nothing of its own: InsecureSkipVerify is
		// set, and a server under RequireAnyClientCert builds no chain either,
		// so state.VerifiedChains is empty and an ACL layered on top would
		// reject every peer. Substitute the chains we authenticated the peer
		// with. state is a copy, so this is local to the callback.
		state.VerifiedChains = chains
		return base(state)
	}
}

func (c *spiffeTLSConfig) GetClientConfig() *tls.Config {
	if cached := c.cachedClient.Load(); cached != nil {
		return cached
	}
	config := c.buildClientConfig()
	c.cachedClient.Store(config)
	return config
}

func (c *spiffeTLSConfig) buildClientConfig() *tls.Config {
	config := c.base.Clone()
	// Go TLS stack will do hostname validation which is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyConnection callback, albeit
	// with an empty set of verified chains. Our callback performs SPIFFE
	// authentication against the peer certificates (see verifyConnection).
	config.InsecureSkipVerify = true
	config.VerifyConnection = c.verifyConnection(config.VerifyConnection)
	if !c.clientDisableAuth {
		// If auth is disabled on the client side we need to not set
		// the GetCertificate callback, because if we do it'll cause
		// the client to block forever if the SPIFFE Workload API
		// doesn't have a client certificate available for us.
		config.GetClientCertificate = spiffeConfig.GetClientCertificate(c.source)
	}
	return config
}

func (c *spiffeTLSConfig) GetServerConfig() *tls.Config {
	if cached := c.cachedServer.Load(); cached != nil {
		return cached
	}
	config := c.buildServerConfig()
	c.cachedServer.Store(config)
	return config
}

func (c *spiffeTLSConfig) buildServerConfig() *tls.Config {
	config := c.base.Clone()

	if !c.clientDisableAuth {
		// Only set client requirement if not disabled in base.
		config.ClientAuth = tls.RequireAnyClientCert
	}

	// Go TLS stack will do hostname validation which is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyConnection callback, albeit
	// with an empty set of verified chains. Our callback performs SPIFFE
	// authentication against the peer certificates (see verifyConnection).
	config.InsecureSkipVerify = true
	if c.clientDisableAuth {
		// No client certificate is requested, so there is no peer to
		// authenticate. crypto/tls runs VerifyConnection even under
		// NoClientCert, so anything inherited from the base config would be
		// called with no peer certificates and no verified chains; drop it
		// rather than leave it to fail closed on every connection.
		config.VerifyConnection = nil
	} else {
		config.VerifyConnection = c.verifyConnection(config.VerifyConnection)
	}
	config.GetCertificate = spiffeConfig.GetCertificate(c.source)
	return config
}
