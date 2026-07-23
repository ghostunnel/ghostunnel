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
	"io"
	"log"
	"sync"
	"testing"

	"github.com/mholt/acmez"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newCachedCertSource builds a cert-backed source over a benchCertificate,
// whose trust store is a real atomic pointer, so a CA-bundle reload can be
// simulated by storing a fresh pool.
func newCachedCertSource(t *testing.T) (*benchCertificate, *certTLSConfig) {
	t.Helper()
	cert := newBenchCertificate()
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))
	server, err := source.GetServerConfig(benchBaseConfig())
	require.NoError(t, err)
	return cert, server.(*certTLSConfig)
}

// Steady-state GetServerConfig must not allocate.
func TestCachedCertServerConfigZeroAllocs(t *testing.T) {
	_, cfg := newCachedCertSource(t)
	cfg.GetServerConfig() // warm the cache

	allocs := testing.AllocsPerRun(100, func() {
		_ = cfg.GetServerConfig()
	})
	assert.Zero(t, allocs, "steady-state GetServerConfig must not allocate")
}

// Steady-state GetClientConfig must not allocate.
func TestCachedCertClientConfigZeroAllocs(t *testing.T) {
	cert := newBenchCertificate()
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))
	client, err := source.GetClientConfig(benchBaseConfig())
	require.NoError(t, err)
	client.GetClientConfig() // warm the cache

	allocs := testing.AllocsPerRun(100, func() {
		_ = client.GetClientConfig()
	})
	assert.Zero(t, allocs, "steady-state GetClientConfig must not allocate")
}

// Without a reload, consecutive calls return the same shared config. This also
// guards against a future per-connection field silently being served stale.
func TestCachedCertServerConfigPointerIdentity(t *testing.T) {
	_, cfg := newCachedCertSource(t)
	first := cfg.GetServerConfig()
	second := cfg.GetServerConfig()
	assert.Same(t, first, second, "GetServerConfig must return the same pointer with no reload")
}

// After the trust store changes, the next call rebuilds with the new pool, and
// subsequent calls return a stable pointer again (rebuilt once per reload).
func TestCachedCertServerConfigReloadVisibility(t *testing.T) {
	cert, cfg := newCachedCertSource(t)

	oldPool := cert.cachedCertPool.Load()
	first := cfg.GetServerConfig()
	assert.Same(t, oldPool, first.ClientCAs, "config should carry the original pool")

	// Simulate a CA-bundle reload: a new pool identity is published.
	newPool := x509.NewCertPool()
	cert.cachedCertPool.Store(newPool)

	rebuilt := cfg.GetServerConfig()
	assert.NotSame(t, first, rebuilt, "a new pool must force a rebuild")
	assert.Same(t, newPool, rebuilt.ClientCAs, "config must carry the new pool")

	again := cfg.GetServerConfig()
	assert.Same(t, rebuilt, again, "no further reload means a stable pointer again")
}

// Same reload visibility for the client path's RootCAs.
func TestCachedCertClientConfigReloadVisibility(t *testing.T) {
	cert := newBenchCertificate()
	source := TLSConfigSourceFromCertificate(cert, log.New(io.Discard, "", 0))
	client, err := source.GetClientConfig(benchBaseConfig())
	require.NoError(t, err)

	first := client.GetClientConfig()
	assert.Same(t, cert.cachedCertPool.Load(), first.RootCAs)

	newPool := x509.NewCertPool()
	cert.cachedCertPool.Store(newPool)

	rebuilt := client.GetClientConfig()
	assert.NotSame(t, first, rebuilt)
	assert.Same(t, newPool, rebuilt.RootCAs, "client config must carry the reloaded pool")
}

// Hammer GetServerConfig from many goroutines while another swaps the pool.
// Run with -race. Every returned config must carry one of the valid pools,
// never a torn or nil value.
func TestCachedCertServerConfigConcurrentReload(t *testing.T) {
	cert, cfg := newCachedCertSource(t)

	pools := []*x509.CertPool{cert.cachedCertPool.Load()}
	for range 8 {
		pools = append(pools, x509.NewCertPool())
	}
	valid := make(map[*x509.CertPool]bool, len(pools))
	for _, p := range pools {
		valid[p] = true
	}

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				cert.cachedCertPool.Store(pools[i%len(pools)])
				i++
			}
		}
	}()

	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 5000 {
				c := cfg.GetServerConfig()
				if !valid[c.ClientCAs] {
					t.Errorf("config carries an unexpected (torn/nil) pool: %p", c.ClientCAs)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	writer.Wait()
}

// Repeated calls must not grow NextProtos, and acme-tls/1 must appear exactly
// once. Guards against appending to a shared slice on every call.
func TestCachedACMENextProtosStable(t *testing.T) {
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
	}
	source := &acmeTLSConfigSource{}
	source.cachedTrustStore.Store(x509.NewCertPool())
	cfg := &acmeTLSConfig{
		base:   base,
		source: source,
	}

	for range 10 {
		c := cfg.GetServerConfig()
		count := 0
		for _, p := range c.NextProtos {
			if p == acmez.ACMETLS1Protocol {
				count++
			}
		}
		assert.Equal(t, 1, count, "acme-tls/1 must appear exactly once")
		assert.Len(t, c.NextProtos, len(base.NextProtos)+1, "NextProtos must not grow across calls")
	}

	// The base config's own NextProtos must not have been mutated/aliased.
	assert.Len(t, base.NextProtos, 2, "build must not append to base.NextProtos")
}

// newCachedACMEConfig builds an acmeTLSConfig whose source carries the given
// trust store, mirroring how TLSConfigSourceFromACME wires the cache.
func newCachedACMEConfig(pool *x509.CertPool) (*acmeTLSConfigSource, *acmeTLSConfig) {
	source := &acmeTLSConfigSource{}
	source.cachedTrustStore.Store(pool)
	return source, &acmeTLSConfig{
		base:   &tls.Config{MinVersion: tls.VersionTLS12},
		source: source,
	}
}

// After the ACME source's trust store changes, the next call rebuilds with the
// new pool; without a reload the pointer is stable. This is the acme analogue
// of TestCachedCertServerConfigReloadVisibility.
func TestCachedACMEServerConfigReloadVisibility(t *testing.T) {
	pool1 := x509.NewCertPool()
	source, cfg := newCachedACMEConfig(pool1)

	first := cfg.GetServerConfig()
	assert.Same(t, pool1, first.ClientCAs, "config should carry the original pool")
	assert.Same(t, first, cfg.GetServerConfig(), "no reload means a stable pointer")

	// Simulate a CA-bundle reload: a new pool identity is published.
	pool2 := x509.NewCertPool()
	source.cachedTrustStore.Store(pool2)

	rebuilt := cfg.GetServerConfig()
	assert.NotSame(t, first, rebuilt, "a new pool must force a rebuild")
	assert.Same(t, pool2, rebuilt.ClientCAs, "config must carry the new pool")
	assert.Same(t, rebuilt, cfg.GetServerConfig(), "stable pointer again after the rebuild")
}

// Steady-state ACME GetServerConfig must not allocate.
func TestCachedACMEServerConfigZeroAllocs(t *testing.T) {
	_, cfg := newCachedACMEConfig(x509.NewCertPool())
	cfg.GetServerConfig() // warm the cache

	allocs := testing.AllocsPerRun(100, func() {
		_ = cfg.GetServerConfig()
	})
	assert.Zero(t, allocs, "steady-state GetServerConfig must not allocate")
}

// Hammer ACME GetServerConfig from many goroutines while another swaps the
// pool. Run with -race. This is the acme analogue of
// TestCachedCertServerConfigConcurrentReload.
func TestCachedACMEServerConfigConcurrentReload(t *testing.T) {
	pools := []*x509.CertPool{x509.NewCertPool()}
	for range 8 {
		pools = append(pools, x509.NewCertPool())
	}
	valid := make(map[*x509.CertPool]bool, len(pools))
	for _, p := range pools {
		valid[p] = true
	}

	source, cfg := newCachedACMEConfig(pools[0])

	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				source.cachedTrustStore.Store(pools[i%len(pools)])
				i++
			}
		}
	}()

	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 5000 {
				c := cfg.GetServerConfig()
				if !valid[c.ClientCAs] {
					t.Errorf("config carries an unexpected (torn/nil) pool: %p", c.ClientCAs)
					return
				}
			}
		}()
	}

	readers.Wait()
	close(stop)
	writer.Wait()
}
