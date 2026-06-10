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
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configCache reads the unexported certCache pointer from a certmagic.Config
// via reflect+unsafe. Brittle to certmagic upgrades; test-only.
func configCache(t *testing.T, cfg *certmagic.Config) *certmagic.Cache {
	t.Helper()
	v := reflect.ValueOf(cfg).Elem().FieldByName("certCache")
	p := unsafe.Pointer(v.UnsafeAddr())
	return *(**certmagic.Cache)(p)
}

// withShortACMEBackoff shortens the package-private backoff schedule so the
// retry loop can be exercised quickly.
func withShortACMEBackoff(t *testing.T) {
	t.Helper()
	origInitial := acmeInitialBackoff
	origMax := acmeMaxBackoff
	acmeInitialBackoff = 5 * time.Millisecond
	acmeMaxBackoff = 20 * time.Millisecond
	t.Cleanup(func() {
		acmeInitialBackoff = origInitial
		acmeMaxBackoff = origMax
	})
}

// alwaysFailACMEServer returns an httptest server that returns 500 for every
// request, plus a counter of total request hits.
func alwaysFailACMEServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// TestACMEInitialIssuanceSingleAttemptNoRetry pins the no-retry behavior:
// MaxAttempts=1 must produce exactly one attempt with no sleep. The hit count
// here is the baseline used by the retry-exhaustion test below.
func TestACMEInitialIssuanceSingleAttemptNoRetry(t *testing.T) {
	origCA, origTestCA, origEmail, origDisableHTTP := saveACMEDefaults()
	defer restoreACMEDefaults(origCA, origTestCA, origEmail, origDisableHTTP)
	withShortACMEBackoff(t)

	server, hits := alwaysFailACMEServer(t)

	cfg := &ACMEConfig{
		FQDN:        "test.example.com",
		Email:       "test@example.com",
		TOSAgreed:   true,
		TestCAURL:   server.URL + "/directory",
		MaxAttempts: 1,
	}

	start := time.Now()
	_, err := TLSConfigSourceFromACME(cfg)
	elapsed := time.Since(start)

	assert.Error(t, err)
	assert.GreaterOrEqual(t, hits.Load(), int32(1), "should hit server at least once")
	assert.Less(t, elapsed, 2*time.Second, "single-attempt loop should complete quickly")
}

// TestACMEInitialIssuanceRetriesExhausted pins the retry loop: with
// MaxAttempts=N (N > 1), the loop must hit the server strictly more than
// MaxAttempts=1 would. Comparing against the single-attempt baseline avoids
// flaking on certmagic's internal request count per attempt.
func TestACMEInitialIssuanceRetriesExhausted(t *testing.T) {
	origCA, origTestCA, origEmail, origDisableHTTP := saveACMEDefaults()
	defer restoreACMEDefaults(origCA, origTestCA, origEmail, origDisableHTTP)
	withShortACMEBackoff(t)

	server, hits := alwaysFailACMEServer(t)

	// Establish baseline: one attempt's worth of requests.
	baselineCfg := &ACMEConfig{
		FQDN: "test.example.com", Email: "test@example.com", TOSAgreed: true,
		TestCAURL: server.URL + "/directory", MaxAttempts: 1,
	}
	_, _ = TLSConfigSourceFromACME(baselineCfg)
	baseline := hits.Load()
	require.GreaterOrEqual(t, baseline, int32(1), "baseline must hit server at least once")
	hits.Store(0)

	// Multi-attempt: must hit server strictly more than baseline.
	const maxAttempts = 3
	cfg := &ACMEConfig{
		FQDN: "test.example.com", Email: "test@example.com", TOSAgreed: true,
		TestCAURL: server.URL + "/directory", MaxAttempts: maxAttempts,
	}
	start := time.Now()
	source, err := TLSConfigSourceFromACME(cfg)
	elapsed := time.Since(start)

	assert.Error(t, err, "should return error after exhausting retries")
	assert.Nil(t, source, "no source when retries are exhausted")
	assert.Greater(t, hits.Load(), baseline,
		"MaxAttempts=%d must produce more hits than MaxAttempts=1 (baseline=%d, got=%d)",
		maxAttempts, baseline, hits.Load())
	assert.Less(t, elapsed, 5*time.Second, "retry loop should be fast with shortened backoff")
}

// TestNewCertmagicConfigDefaultCache: with RenewCheckInterval=0, every Config
// shares the certmagic.Default singleton cache (production path).
func TestNewCertmagicConfigDefaultCache(t *testing.T) {
	refCache := configCache(t, certmagic.NewDefault())
	require.NotNil(t, refCache)

	aCache := configCache(t, newCertmagicConfig(0))
	bCache := configCache(t, newCertmagicConfig(0))

	assert.Same(t, refCache, aCache, "renew=0 must share certmagic.Default cache")
	assert.Same(t, aCache, bCache, "two renew=0 configs must share the same cache")
}

// TestNewCertmagicConfigCustomRenewInterval: a non-zero RenewCheckInterval
// must produce a fresh Cache, not the certmagic.Default singleton.
func TestNewCertmagicConfigCustomRenewInterval(t *testing.T) {
	defaultCache := configCache(t, certmagic.NewDefault())
	require.NotNil(t, defaultCache)

	custom := newCertmagicConfig(30 * time.Second)
	customCache := configCache(t, custom)
	require.NotNil(t, customCache)

	custom2Cache := configCache(t, newCertmagicConfig(45*time.Second))

	assert.NotSame(t, defaultCache, customCache, "custom-interval must not share default cache")
	assert.NotSame(t, customCache, custom2Cache, "two custom-interval calls must each get a fresh cache")

	assert.NotNil(t, custom.Logger)
	assert.NotEmpty(t, custom.Issuers, "issuers must be copied from certmagic.Default")
}
