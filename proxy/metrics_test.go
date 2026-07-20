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

	"github.com/ghostunnel/ghostunnel/metrics"
	"github.com/stretchr/testify/assert"
)

// TestNilMetricsAreNoOps verifies that the no-op metrics handles record
// nothing. This is what makes skipping collection (when no sink is configured)
// free on the connection hot path: updates land on no-op handles. Critically, a
// no-op Timer must still not swallow work — but since we never route the
// connection handler through Timer.Time (we use UpdateSince), all that matters
// here is that updates are observably no-ops.
func TestNilMetricsAreNoOps(t *testing.T) {
	m := metrics.NilMetrics()

	counters := []metrics.Counter{
		m.OpenCounter, m.ConnTimeoutCounter, m.TotalCounter, m.SuccessCounter,
		m.ErrorCounter, m.HandshakeTimeoutCounter,
	}
	for _, c := range counters {
		// Exercising a no-op handle must not panic and must not record anywhere.
		c.Inc(1)
		c.Dec(1)
	}

	timers := []metrics.Timer{m.HandshakeTimer, m.ConnTimer}
	for _, tm := range timers {
		tm.UpdateSince(time.Now())
	}
}

// TestLiveMetricsRegisterCanonicalNames verifies that LiveMetrics registers
// every metric under its canonical, externally-visible name on the supplied
// registry, and that recording through a handle is observable under that name.
// The names are part of Ghostunnel's exported surface, so this guards against
// an accidental rename.
func TestLiveMetricsRegisterCanonicalNames(t *testing.T) {
	registry := metrics.NewRegistry("ghostunnel")
	m := metrics.LiveMetrics(registry)

	// Every counter must be readable by its canonical name.
	for _, name := range []string{
		"conn.open", "conn.timeout", "accept.total", "accept.success",
		"accept.error", "accept.timeout",
	} {
		_, ok := registry.SingleValue(name)
		assert.True(t, ok, "counter %q must be registered", name)
	}
	for _, name := range []string{"conn.handshake", "conn.lifetime"} {
		_, ok := registry.TimerCount(name)
		assert.True(t, ok, "timer %q must be registered", name)
	}

	// Live handles actually record.
	m.TotalCounter.Inc(1)
	v, ok := registry.SingleValue("accept.total")
	assert.True(t, ok)
	assert.Equal(t, int64(1), v, "live counter must record")
}

// TestNewMetricsWiring pins the injection seam New relies on: passing nil keeps
// the historical default-registry behavior, while NilMetrics yields a proxy
// whose hot-path handles never touch a registry. This is the proxy-side guard
// against silently re-enabling collection.
func TestNewMetricsWiring(t *testing.T) {
	p := proxyForTest(&failingListener{}, nil)
	assert.Same(t, defaultMetrics, p.metrics, "nil handle must fall back to the default metrics")

	nilHandles := metrics.NilMetrics()
	nilP := New(&failingListener{}, Timeouts{Connect: time.Second, Close: time.Second, MaxLifetime: time.Second}, 1, nil, &testLogger{}, 0, ProxyProtocolOff, nilHandles)
	assert.Same(t, nilHandles, nilP.metrics, "NilMetrics handles must be used verbatim")
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

	p := New(incoming, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, metrics.NilMetrics())
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
