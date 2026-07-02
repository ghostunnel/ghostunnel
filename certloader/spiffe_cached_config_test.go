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
	"io"
	"log"
	"sync"
	"testing"

	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for the SPIFFE cached TLS configs. Unlike the cert- and acme-backed
// sources there is no reloadable trust store (the X509Source maintains itself),
// so the cache has no invalidation key: build once, cache forever. That makes
// pointer stability and the correctness of the single build critical — a wrong
// config here would never self-correct.

// newCachedSPIFFEConfig builds a spiffeTLSConfig against a fake Workload API.
func newCachedSPIFFEConfig(t *testing.T, clientDisableAuth bool) *spiffeTLSConfig {
	t.Helper()

	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/cache-test"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(&spiffetest.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{svid},
	})
	t.Cleanup(workloadAPI.Stop)

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), clientDisableAuth, log.New(io.Discard, "", 0))
	require.NoError(t, err)
	t.Cleanup(func() { _ = source.(*spiffeTLSConfigSource).Close() })

	server, err := source.GetServerConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	require.NoError(t, err)
	return server.(*spiffeTLSConfig)
}

// Consecutive calls must return the same shared config on both paths.
func TestCachedSPIFFEConfigPointerIdentity(t *testing.T) {
	cfg := newCachedSPIFFEConfig(t, false)

	assert.Same(t, cfg.GetClientConfig(), cfg.GetClientConfig(),
		"GetClientConfig must return the same pointer")
	assert.Same(t, cfg.GetServerConfig(), cfg.GetServerConfig(),
		"GetServerConfig must return the same pointer")
}

// Steady-state Get*Config must not allocate.
func TestCachedSPIFFEConfigZeroAllocs(t *testing.T) {
	cfg := newCachedSPIFFEConfig(t, false)
	cfg.GetClientConfig() // warm both caches
	cfg.GetServerConfig()

	allocs := testing.AllocsPerRun(100, func() {
		_ = cfg.GetClientConfig()
	})
	assert.Zero(t, allocs, "steady-state GetClientConfig must not allocate")

	allocs = testing.AllocsPerRun(100, func() {
		_ = cfg.GetServerConfig()
	})
	assert.Zero(t, allocs, "steady-state GetServerConfig must not allocate")
}

// The clientDisableAuth branch: with auth enabled the client sends a
// certificate and the server requires one; with it disabled neither happens.
// This pins the one conditional inside the build-once-cache-forever path.
func TestCachedSPIFFEConfigClientAuthBranch(t *testing.T) {
	enabled := newCachedSPIFFEConfig(t, false)
	assert.NotNil(t, enabled.GetClientConfig().GetClientCertificate,
		"client must offer a certificate when auth is enabled")
	assert.Equal(t, tls.RequireAnyClientCert, enabled.GetServerConfig().ClientAuth,
		"server must require a client certificate when auth is enabled")

	disabled := newCachedSPIFFEConfig(t, true)
	assert.Nil(t, disabled.GetClientConfig().GetClientCertificate,
		"client must not block on a certificate when auth is disabled")
	assert.NotEqual(t, tls.RequireAnyClientCert, disabled.GetServerConfig().ClientAuth,
		"server must not require a client certificate when auth is disabled")
}

// Hammer both getters from many goroutines after warming. Run with -race.
// Every call must return the already-cached pointer.
func TestCachedSPIFFEConfigConcurrent(t *testing.T) {
	cfg := newCachedSPIFFEConfig(t, false)
	client := cfg.GetClientConfig()
	server := cfg.GetServerConfig()

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 2000; n++ {
				if cfg.GetClientConfig() != client {
					t.Error("GetClientConfig returned a different pointer")
					return
				}
				if cfg.GetServerConfig() != server {
					t.Error("GetServerConfig returned a different pointer")
					return
				}
			}
		}()
	}
	wg.Wait()
}
