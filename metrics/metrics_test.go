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

package metrics

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixture builds a registry with a known set of observations:
//   - accept.total = 3, accept.error = 1
//   - conn.open = 2 (Inc'd 3, Dec'd 1)
//   - conn.handshake observed at 10, 20, 30 ns (count 3, min 10, max 30, mean 20)
func fixture(t *testing.T) (*Registry, *Metrics) {
	t.Helper()
	r := NewRegistry("ghostunnel")
	m := LiveMetrics(r)

	m.TotalCounter.Inc(1)
	m.TotalCounter.Inc(1)
	m.TotalCounter.Inc(1)
	m.ErrorCounter.Inc(1)

	m.OpenCounter.Inc(1)
	m.OpenCounter.Inc(1)
	m.OpenCounter.Inc(1)
	m.OpenCounter.Dec(1)

	ht := m.HandshakeTimer.(*timer)
	ht.observeNanos(10)
	ht.observeNanos(20)
	ht.observeNanos(30)

	return r, m
}

// jsonByMetric decodes the JSON export into a name→value map.
func jsonByMetric(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var entries []map[string]any
	require.NoError(t, json.Unmarshal(raw, &entries))
	out := make(map[string]any, len(entries))
	for _, e := range entries {
		name, _ := e["metric"].(string)
		out[name] = e["value"]
		// Every entry must carry the four sq-metrics fields.
		assert.Contains(t, e, "timestamp")
		assert.Contains(t, e, "hostname")
		assert.Contains(t, e, "metric")
		assert.Contains(t, e, "value")
	}
	return out
}

func TestJSONFieldSet(t *testing.T) {
	r, _ := fixture(t)
	raw, err := r.jsonBytes()
	require.NoError(t, err)
	byName := jsonByMetric(t, raw)

	// Counters and the gauge-like conn.open are bare single values.
	assert.EqualValues(t, 3, byName["ghostunnel.accept.total"])
	assert.EqualValues(t, 1, byName["ghostunnel.accept.error"])
	assert.EqualValues(t, 2, byName["ghostunnel.conn.open"])

	// Timer expands to exactly count/min/max/mean + the four percentiles.
	assert.EqualValues(t, 3, byName["ghostunnel.conn.handshake.count"])
	assert.EqualValues(t, 10, byName["ghostunnel.conn.handshake.min"])
	assert.EqualValues(t, 30, byName["ghostunnel.conn.handshake.max"])
	assert.EqualValues(t, 20, byName["ghostunnel.conn.handshake.mean"])
	assert.Contains(t, byName, "ghostunnel.conn.handshake.50-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.75-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.95-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.99-percentile")

	// Deprecated/never-present-in-JSON fields must be absent.
	for name := range byName {
		for _, banned := range []string{"std-dev", "std_dev", "variance", "999-percentile",
			"count_ps", "one-minute", "five-minute", "fifteen-minute", "mean-rate",
			"rate1", "rate5", "rate15", "rate_mean", "-percentile."} {
			assert.NotContains(t, name, banned, "JSON must not contain %q", banned)
		}
	}
}

func TestJSONValueTypes(t *testing.T) {
	// count/min/max must encode as integers, mean/percentiles as floats, to stay
	// byte-compatible with go-sq-metrics' output.
	r, _ := fixture(t)
	raw, err := r.jsonBytes()
	require.NoError(t, err)
	s := string(raw)
	// Keys within each object are sorted alphabetically (hostname, metric,
	// timestamp, value), exactly as go-sq-metrics' map[string]interface{}
	// marshalled them, so a count entry ends in `,"value":3}`.
	assert.Contains(t, s, `"metric":"ghostunnel.accept.total","timestamp":`)
	assert.Contains(t, s, `"value":3}`, "counts encode as integers")
	assert.Contains(t, s, `"metric":"ghostunnel.conn.handshake.count","timestamp":`)
	// mean of {10,20,30} is exactly 20; an integer-valued float64 encodes
	// without a decimal point in Go, identical to the integer encoding.
	assert.Contains(t, s, "ghostunnel.conn.handshake.mean")
}

func TestJSONEmptyTimerIsZeroed(t *testing.T) {
	// A timer with no observations must emit zeros (never NaN, which would make
	// json.Marshal fail).
	r := NewRegistry("ghostunnel")
	_ = LiveMetrics(r)
	raw, err := r.jsonBytes()
	require.NoError(t, err, "empty timers must not produce NaN values")
	byName := jsonByMetric(t, raw)
	assert.EqualValues(t, 0, byName["ghostunnel.conn.handshake.count"])
	assert.EqualValues(t, 0, byName["ghostunnel.conn.handshake.min"])
	assert.EqualValues(t, 0, byName["ghostunnel.conn.handshake.99-percentile"])
}

func TestGraphiteFieldSet(t *testing.T) {
	r, _ := fixture(t)
	var buf bytes.Buffer
	r.writeGraphite(&buf, 1700000000)
	out := buf.String()
	lines := strings.Split(strings.TrimSpace(out), "\n")

	got := map[string]bool{}
	for _, l := range lines {
		fields := strings.Fields(l)
		require.Len(t, fields, 3, "graphite line must be '<path> <value> <ts>': %q", l)
		assert.Equal(t, "1700000000", fields[2], "timestamp column")
		got[fields[0]] = true
	}

	// Kept fields.
	assert.True(t, got["ghostunnel.accept.total.count"], "counter emits .count")
	assert.True(t, got["ghostunnel.conn.open.count"], "conn.open keeps .count (not .value)")
	for _, suffix := range []string{"count", "min", "max", "mean",
		"50-percentile", "75-percentile", "95-percentile", "99-percentile"} {
		assert.True(t, got["ghostunnel.conn.handshake."+suffix], "timer keeps .%s", suffix)
	}
	// A runtime gauge keeps .value.
	assert.False(t, got["ghostunnel.accept.total.value"], "counters must not emit .value")

	// Dropped fields.
	for _, banned := range []string{
		"ghostunnel.accept.total.count_ps",
		"ghostunnel.conn.handshake.std-dev",
		"ghostunnel.conn.handshake.999-percentile",
		"ghostunnel.conn.handshake.count_ps",
		"ghostunnel.conn.handshake.one-minute",
		"ghostunnel.conn.handshake.five-minute",
		"ghostunnel.conn.handshake.fifteen-minute",
		"ghostunnel.conn.handshake.mean-rate",
	} {
		assert.False(t, got[banned], "graphite must not emit %q", banned)
	}

	// Values for the deterministic timer fields.
	assert.Contains(t, out, "ghostunnel.conn.handshake.count 3 1700000000\n")
	assert.Contains(t, out, "ghostunnel.conn.handshake.min 10 1700000000\n")
	assert.Contains(t, out, "ghostunnel.conn.handshake.max 30 1700000000\n")
	assert.Contains(t, out, "ghostunnel.conn.handshake.mean 20.00 1700000000\n")
}

func TestPrometheusNative(t *testing.T) {
	r, _ := fixture(t)
	fams, err := r.prom.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
	}

	// conn.open is a gauge; counters are counters; timers are summaries named
	// without the historical "_timer" suffix.
	assert.True(t, names["ghostunnel_conn_open"], "conn.open present")
	assert.True(t, names["ghostunnel_accept_total"], "accept.total present")
	assert.True(t, names["ghostunnel_conn_handshake"], "timer is a native summary")
	assert.False(t, names["ghostunnel_conn_handshake_timer"], "no legacy _timer suffix")

	// go_*/process_* collectors remain.
	hasGo, hasProcess := false, false
	for n := range names {
		if strings.HasPrefix(n, "go_") {
			hasGo = true
		}
		if strings.HasPrefix(n, "process_") {
			hasProcess = true
		}
	}
	assert.True(t, hasGo, "go_* collectors registered")
	assert.True(t, hasProcess, "process_* collectors registered")

	// The summary carries _sum, _count and the four quantiles; no std_dev/variance/rate.
	body := renderProm(t, r)
	assert.Contains(t, body, "ghostunnel_conn_handshake_sum")
	assert.Contains(t, body, "ghostunnel_conn_handshake_count 3")
	assert.Contains(t, body, `ghostunnel_conn_handshake{quantile="0.5"}`)
	assert.Contains(t, body, `ghostunnel_conn_handshake{quantile="0.99"}`)
	for _, banned := range []string{"std_dev", "variance", "_rate1", "_rate5", "_rate15", "rate_mean", "_timer_bucket"} {
		assert.NotContains(t, body, banned, "prometheus must not contain %q", banned)
	}
}

func TestTimerObservationsAreNanoseconds(t *testing.T) {
	// The percentiles must come out in the same units as min/max/mean (ns), so a
	// median of {10,20,30}ns is ~20, not ~2e-8 (seconds).
	r, _ := fixture(t)
	for _, tr := range r.snapshot().timers {
		if tr.dotted != "conn.handshake" {
			continue
		}
		assert.InDelta(t, 20.0, tr.p50, 15.0, "p50 should be ~20ns")
		assert.GreaterOrEqual(t, tr.p99, 20.0, "p99 within observed range")
	}
}

func TestTimerFirstObservationMinMax(t *testing.T) {
	// A timer's very first observation must surface as both min and max — never
	// the min sentinel (math.MaxInt64). This pins the store ordering in
	// observeNanos and the clamp in readTimer.
	r := NewRegistry("ghostunnel")
	m := LiveMetrics(r)
	m.HandshakeTimer.(*timer).observeNanos(42)

	var got timerReading
	for _, tr := range r.snapshot().timers {
		if tr.dotted == "conn.handshake" {
			got = tr
		}
	}
	assert.EqualValues(t, 1, got.count)
	assert.EqualValues(t, 42, got.min, "first observation must be the min")
	assert.EqualValues(t, 42, got.max, "first observation must be the max")
	assert.Less(t, got.min, int64(1<<62), "min sentinel must never leak to the wire")
}

func TestSingleValueAndTimerCount(t *testing.T) {
	r, _ := fixture(t)
	v, ok := r.SingleValue("conn.open")
	assert.True(t, ok)
	assert.EqualValues(t, 2, v)

	c, ok := r.TimerCount("conn.handshake")
	assert.True(t, ok)
	assert.EqualValues(t, 3, c)

	_, ok = r.SingleValue("does.not.exist")
	assert.False(t, ok)
}

func TestNilMetricsAreNoOps(t *testing.T) {
	m := NilMetrics()
	assert.IsType(t, nopCounter{}, m.OpenCounter)
	assert.IsType(t, nopCounter{}, m.ErrorCounter)
	assert.IsType(t, nopTimer{}, m.ConnTimer)
	// Exercising them must not panic.
	m.OpenCounter.Inc(1)
	m.OpenCounter.Dec(1)
	m.ConnTimer.UpdateSince(time.Now())
}

func TestRuntimeCollector(t *testing.T) {
	r := NewRegistry("ghostunnel")
	_ = LiveMetrics(r)
	r.StartRuntimeCollector(time.Hour) // immediate collect, then idle ticker

	raw, err := r.jsonBytes()
	require.NoError(t, err)
	byName := jsonByMetric(t, raw)

	// A representative set of runtime gauges must be present and non-negative.
	for _, name := range []string{
		"ghostunnel.runtime.mem.alloc",
		"ghostunnel.runtime.mem.heap.objects",
		"ghostunnel.runtime.goroutines",
		"ghostunnel.runtime.mem.gc.num-gc",
	} {
		v, ok := byName[name]
		assert.True(t, ok, "missing runtime gauge %q", name)
		assert.NotNil(t, v)
	}
	// cpu-fraction is a float gauge.
	assert.Contains(t, byName, "ghostunnel.runtime.mem.gc.cpu-fraction")
	// GC duration is a timer (expands to .count etc.).
	assert.Contains(t, byName, "ghostunnel.runtime.mem.gc.duration.count")
}

func TestFlatten(t *testing.T) {
	assert.Equal(t, "conn_open", flatten("conn.open"))
	assert.Equal(t, "runtime_mem_total_alloc", flatten("runtime.mem.total-alloc"))
	assert.Equal(t, "ghostunnel", flatten("ghostunnel"))
}

func TestPrefixApplied(t *testing.T) {
	r := NewRegistry("custom_prefix")
	_ = LiveMetrics(r)
	raw, err := r.jsonBytes()
	require.NoError(t, err)
	byName := jsonByMetric(t, raw)
	assert.Contains(t, byName, "custom_prefix.accept.total")
	// Prometheus namespace is the flattened prefix.
	fams, _ := r.prom.Gather()
	found := false
	for _, f := range fams {
		if f.GetName() == "custom_prefix_accept_total" {
			found = true
		}
	}
	assert.True(t, found, "prometheus namespace uses flattened prefix")
}

// renderProm renders the native Prometheus text exposition for r.
func renderProm(t *testing.T, r *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/_metrics/prometheus", nil)
	r.PrometheusHandler().ServeHTTP(rec, req)
	return rec.Body.String()
}
