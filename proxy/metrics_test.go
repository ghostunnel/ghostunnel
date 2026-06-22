/*-
 * Copyright 2015 Square Inc.
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

package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	metrics "github.com/rcrowley/go-metrics"
	"github.com/stretchr/testify/assert"
)

// TestNilMetricsAreNoOps verifies that the no-op metrics handles record
// nothing. This is what makes skipping collection (when no sink is configured)
// free on the connection hot path: updates land on Nil* handles. Critically,
// a no-op Timer must still not swallow work — but since we never route the
// connection handler through Timer.Time (we use UpdateSince), all that matters
// here is that updates are observably no-ops.
func TestNilMetricsAreNoOps(t *testing.T) {
	m := NilMetrics()

	counters := []metrics.Counter{
		m.OpenCounter, m.ConnTimeoutCounter, m.TotalCounter, m.SuccessCounter,
		m.ErrorCounter, m.HandshakeTimeoutCounter,
	}
	for _, c := range counters {
		assert.IsType(t, metrics.NilCounter{}, c, "expected a no-op counter")
		c.Inc(1)
		assert.Equal(t, int64(0), c.Count(), "no-op counter must not record")
	}

	timers := []metrics.Timer{m.HandshakeTimer, m.ConnTimer}
	for _, tm := range timers {
		assert.IsType(t, metrics.NilTimer{}, tm, "expected a no-op timer")
		tm.UpdateSince(time.Now())
		assert.Equal(t, int64(0), tm.Count(), "no-op timer must not record")
	}
}

// TestLiveMetricsRegisterCanonicalNames verifies that LiveMetrics registers
// every metric under its canonical, externally-visible name on the supplied
// registry, and that the returned handles are the registered ones. The names
// are part of Ghostunnel's exported surface, so this guards against an
// accidental rename.
func TestLiveMetricsRegisterCanonicalNames(t *testing.T) {
	registry := metrics.NewRegistry()
	m := LiveMetrics(registry)

	expected := map[string]any{
		"conn.open":      m.OpenCounter,
		"conn.timeout":   m.ConnTimeoutCounter,
		"accept.total":   m.TotalCounter,
		"accept.success": m.SuccessCounter,
		"accept.error":   m.ErrorCounter,
		"accept.timeout": m.HandshakeTimeoutCounter,
		"conn.handshake": m.HandshakeTimer,
		"conn.lifetime":  m.ConnTimer,
	}
	for name, handle := range expected {
		got := registry.Get(name)
		assert.NotNil(t, got, "metric %q must be registered", name)
		assert.Equal(t, handle, got, "metric %q handle must match the registered one", name)
	}

	// Live handles actually record.
	m.TotalCounter.Inc(1)
	assert.Equal(t, int64(1), m.TotalCounter.Count(), "live counter must record")
}

// TestNewMetricsWiring pins the injection seam New relies on: passing nil keeps
// the historical default-registry behavior, while NilMetrics yields a proxy
// whose hot-path handles never touch a registry. This is the proxy-side guard
// against silently re-enabling collection.
func TestNewMetricsWiring(t *testing.T) {
	p := proxyForTest(&failingListener{}, nil)
	assert.Same(t, defaultMetrics, p.metrics, "nil handle must fall back to the default registry")

	nilP := New(&failingListener{}, time.Second, time.Second, time.Second, 1, nil, &testLogger{}, 0, ProxyProtocolOff, NilMetrics())
	assert.IsType(t, metrics.NilCounter{}, nilP.metrics.ErrorCounter, "NilMetrics must produce no-op handles")
	assert.IsType(t, metrics.NilTimer{}, nilP.metrics.ConnTimer, "NilMetrics must produce no-op handles")
}

// TestNilMetricsProxyForwardsData is the regression guard for the hot-path
// restructure: the connection handler used to be wrapped in connTimer.Time(fn),
// but a no-op Timer's Time() never runs fn — so with NilMetrics that would have
// silently dropped every connection. This proves a NilMetrics proxy still
// forwards bytes end-to-end.
func TestNilMetricsProxyForwardsData(t *testing.T) {
	// Plain TCP listener (incoming) and backend (target).
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}

	p := New(incoming, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, NilMetrics())
	go p.Accept()
	defer p.Shutdown()

	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)
	defer src.Close()

	dst, err := target.Accept()
	assert.Nil(t, err)
	defer dst.Close()

	_, err = src.Write([]byte("ping"))
	assert.Nil(t, err)

	_ = dst.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4)
	n, err := io.ReadFull(dst, buf)
	assert.Nil(t, err, "backend must receive forwarded data even with no-op metrics")
	assert.Equal(t, "ping", string(buf[:n]))
}
