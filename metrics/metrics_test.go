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
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dto "github.com/prometheus/client_model/go"
)

// fixture builds a registry with a known set of observations:
//   - accept.total = 3, accept.error = 1
//   - conn.open = 2 (Inc'd 3, Dec'd 1)
//   - conn.handshake observed at 10ms, 20ms, 30ms (count 3, mean 20ms); values
//     are in the millisecond range so they land inside the handshake histogram's
//     bucket layout and the interpolated percentiles are meaningful.
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
	ht.observeNanos(10_000_000)
	ht.observeNanos(20_000_000)
	ht.observeNanos(30_000_000)

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

	// Timer expands to exactly count/mean + the four percentiles (min/max were
	// dropped in the histogram migration).
	assert.EqualValues(t, 3, byName["ghostunnel.conn.handshake.count"])
	assert.EqualValues(t, 20_000_000, byName["ghostunnel.conn.handshake.mean"])
	assert.Contains(t, byName, "ghostunnel.conn.handshake.50-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.75-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.95-percentile")
	assert.Contains(t, byName, "ghostunnel.conn.handshake.99-percentile")

	// Deprecated/dropped/never-present-in-JSON fields must be absent.
	for name := range byName {
		for _, banned := range []string{".min", ".max", "std-dev", "std_dev", "variance",
			"999-percentile", "count_ps", "one-minute", "five-minute", "fifteen-minute",
			"mean-rate", "rate1", "rate5", "rate15", "rate_mean", "-percentile."} {
			assert.NotContains(t, name, banned, "JSON must not contain %q", banned)
		}
	}
}

func TestJSONIntegerEncoding(t *testing.T) {
	// A counter of 3 encodes as the JSON number 3 (Go marshals an integer-valued
	// float64 without a decimal point), not 3.0.
	r, _ := fixture(t)
	raw, err := r.jsonBytes()
	require.NoError(t, err)
	s := string(raw)
	assert.Contains(t, s, `"value":3`, "counts encode as integers, not 3.0")
	assert.NotContains(t, s, `"value":3.0`)
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
	assert.EqualValues(t, 0, byName["ghostunnel.conn.handshake.99-percentile"])
}

func TestGraphiteFieldSet(t *testing.T) {
	r, _ := fixture(t)
	var buf bytes.Buffer
	r.writeGraphite(&buf, 1700000000)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")

	// path -> value column. Order is not significant.
	got := map[string]string{}
	for _, l := range lines {
		fields := strings.Fields(l)
		require.Len(t, fields, 3, "graphite line must be '<path> <value> <ts>': %q", l)
		assert.Equal(t, "1700000000", fields[2], "timestamp column")
		got[fields[0]] = fields[1]
	}

	// Kept fields.
	assert.Contains(t, got, "ghostunnel.accept.total.count", "counter emits .count")
	assert.Contains(t, got, "ghostunnel.conn.open.count", "conn.open keeps .count (not .value)")
	for _, suffix := range []string{"count", "mean",
		"50-percentile", "75-percentile", "95-percentile", "99-percentile"} {
		assert.Contains(t, got, "ghostunnel.conn.handshake."+suffix, "timer keeps .%s", suffix)
	}
	// A counter must not emit .value.
	assert.NotContains(t, got, "ghostunnel.accept.total.value", "counters must not emit .value")

	// Dropped fields (min/max were removed in the histogram migration).
	for _, banned := range []string{
		"ghostunnel.conn.handshake.min",
		"ghostunnel.conn.handshake.max",
		"ghostunnel.accept.total.count_ps",
		"ghostunnel.conn.handshake.std-dev",
		"ghostunnel.conn.handshake.999-percentile",
		"ghostunnel.conn.handshake.count_ps",
		"ghostunnel.conn.handshake.one-minute",
		"ghostunnel.conn.handshake.five-minute",
		"ghostunnel.conn.handshake.fifteen-minute",
		"ghostunnel.conn.handshake.mean-rate",
	} {
		assert.NotContains(t, got, banned, "graphite must not emit %q", banned)
	}

	// Values for the deterministic timer fields (compared numerically, not by
	// exact formatting).
	floatVal := func(path string) float64 {
		f, err := strconv.ParseFloat(got[path], 64)
		require.NoError(t, err, "value for %q must parse as a number", path)
		return f
	}
	assert.EqualValues(t, 3, floatVal("ghostunnel.conn.handshake.count"))
	assert.EqualValues(t, 20_000_000, floatVal("ghostunnel.conn.handshake.mean"))
}

func TestPrometheusNative(t *testing.T) {
	r, _ := fixture(t)
	fams, err := r.prom.Gather()
	require.NoError(t, err)
	names := map[string]bool{}
	for _, f := range fams {
		names[f.GetName()] = true
	}

	// conn.open is a gauge; counters are counters; timers are histograms named
	// without the historical "_timer" suffix.
	assert.True(t, names["ghostunnel_conn_open"], "conn.open present")
	assert.True(t, names["ghostunnel_accept_total"], "accept.total present")
	assert.True(t, names["ghostunnel_conn_handshake"], "timer is a native histogram")
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
	// The process_* collector reads from /proc, which FreeBSD does not mount by
	// default, so those metrics are absent there (the collector no-ops silently).
	if runtime.GOOS != "freebsd" {
		assert.True(t, hasProcess, "process_* collectors registered")
	}

	// The histogram carries _sum, _count and the classic _bucket{le=...} series;
	// no summary quantiles, std_dev/variance/rate, or legacy _timer_bucket.
	body := renderProm(t, r)
	assert.Contains(t, body, "ghostunnel_conn_handshake_sum")
	assert.Contains(t, body, "ghostunnel_conn_handshake_count 3")
	assert.Contains(t, body, `ghostunnel_conn_handshake_bucket{le=`)
	assert.NotContains(t, body, `ghostunnel_conn_handshake{quantile=`, "timers are histograms, not summaries")
	for _, banned := range []string{"std_dev", "variance", "_rate1", "_rate5", "_rate15", "rate_mean", "_timer_bucket"} {
		assert.NotContains(t, body, banned, "prometheus must not contain %q", banned)
	}
}

func TestTimerObservationsAreNanoseconds(t *testing.T) {
	// The percentiles must come out in the same units as mean (ns): the fixture
	// observes {10,20,30}ms, so a median near 2e7 ns confirms the histogram
	// buckets and interpolation are in nanoseconds — not seconds (~0.02) or some
	// other scale. The exact interpolated value depends on bucket layout, so the
	// bound is deliberately wide.
	r, _ := fixture(t)
	for _, tr := range r.snapshot().timers {
		if tr.dotted != "conn.handshake" {
			continue
		}
		assert.Greater(t, tr.p50, 1e6, "p50 must be in the millisecond (ns) range, not seconds")
		assert.Less(t, tr.p50, 1e8, "p50 must be near the observed 10-30ms range")
		assert.GreaterOrEqual(t, tr.p99, tr.p50, "p99 must be >= p50")
	}
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

func TestNZClampsNaNAndInf(t *testing.T) {
	// nz keeps NaN/Inf off the wire: interpolating a percentile from an empty
	// histogram yields NaN, which would fail json.Marshal and emit "NaN" to
	// Graphite.
	assert.EqualValues(t, 0, nz(math.NaN()))
	assert.EqualValues(t, 0, nz(math.Inf(1)))
	assert.EqualValues(t, 0, nz(math.Inf(-1)))
	assert.Equal(t, 12.5, nz(12.5), "finite values pass through unchanged")
}

// mkBucket builds a gathered cumulative bucket with the given upper bound and
// cumulative count.
func mkBucket(upper float64, cum uint64) *dto.Bucket {
	return &dto.Bucket{UpperBound: &upper, CumulativeCount: &cum}
}

func TestHistogramQuantile(t *testing.T) {
	// Cumulative buckets le=10 -> 2, le=20 -> 5, le=30 -> 10 (total 10).
	// client_golang omits the +Inf bucket; histogramQuantile synthesizes it.
	buckets := []*dto.Bucket{mkBucket(10, 2), mkBucket(20, 5), mkBucket(30, 10)}

	// No observations -> 0 (never NaN out of the quantile itself).
	assert.Equal(t, 0.0, histogramQuantile(0.5, buckets, 0))
	assert.Equal(t, 0.0, histogramQuantile(0.5, nil, 10))

	// p50 rank=5 lands exactly at the le=20 boundary: interpolate within (10,20],
	// rankInBucket = 5-2 = 3 of 3 -> the upper edge, 20.
	assert.InDelta(t, 20.0, histogramQuantile(0.5, buckets, 10), 1e-9)
	// p10 rank=1 lands in the first bucket (0,10], 1 of 2 -> 5.
	assert.InDelta(t, 5.0, histogramQuantile(0.1, buckets, 10), 1e-9)

	// Quantiles are non-decreasing in q and never exceed the top finite bound.
	prev := 0.0
	for _, q := range []float64{0.1, 0.25, 0.5, 0.75, 0.9, 0.99} {
		v := histogramQuantile(q, buckets, 10)
		assert.GreaterOrEqual(t, v, prev, "quantiles must be non-decreasing in q")
		assert.LessOrEqual(t, v, 30.0, "must not exceed the highest finite bound")
		assert.False(t, math.IsInf(v, 0) || math.IsNaN(v), "must be finite")
		prev = v
	}
}

func TestHistogramQuantileInfBucketCap(t *testing.T) {
	// When the rank lands in the implicit +Inf bucket (observations above the top
	// finite bound), report the highest finite bound rather than +Inf.
	buckets := []*dto.Bucket{mkBucket(10, 1), mkBucket(20, 2)}
	got := histogramQuantile(0.99, buckets, 10) // ranks >0.2 land in +Inf
	assert.Equal(t, 20.0, got, "ranks above the top finite bucket cap at that bound")
	assert.False(t, math.IsInf(got, 1), "must never return +Inf")
}

func TestHistogramQuantileExplicitInfBucket(t *testing.T) {
	// A gatherer that includes the +Inf bucket explicitly must not have it
	// double-appended and must still cap at the highest finite bound.
	buckets := []*dto.Bucket{mkBucket(10, 1), mkBucket(math.Inf(1), 10)}
	assert.Equal(t, 10.0, histogramQuantile(0.99, buckets, 10))
}

func TestReadersHandleMissingFamily(t *testing.T) {
	// When Gather() reports no family for a descriptor, the readers must return a
	// zeroed reading rather than dereference a nil family.
	s := readSingle(&descriptor{dotted: "x", kind: kindCounter}, nil)
	assert.Equal(t, "x", s.dotted)
	assert.Zero(t, s.value)

	tr := readTimer(&descriptor{dotted: "y", kind: kindTimer}, nil)
	assert.Equal(t, "y", tr.dotted)
	assert.Zero(t, tr.count)
}

func TestTimerUpdateSinceRecords(t *testing.T) {
	// UpdateSince is the hot-path entry point (observeNanos is the internal one).
	r := NewRegistry("ghostunnel")
	m := LiveMetrics(r)
	m.HandshakeTimer.UpdateSince(time.Now().Add(-10 * time.Millisecond))

	c, ok := r.TimerCount("conn.handshake")
	require.True(t, ok)
	assert.EqualValues(t, 1, c)
	for _, tr := range r.snapshot().timers {
		if tr.dotted == "conn.handshake" {
			assert.Positive(t, tr.mean, "elapsed duration must be recorded as a positive mean")
			assert.Positive(t, tr.p50, "elapsed duration must interpolate to a positive p50")
		}
	}
}

func TestTimerCountMissing(t *testing.T) {
	r, _ := fixture(t)
	_, ok := r.TimerCount("does.not.exist")
	assert.False(t, ok)
}

func TestGraphiteGaugeEmitsValue(t *testing.T) {
	// The fixture has only counters and timers; a runtime gauge exercises the
	// ".value" rendering branch.
	r := NewRegistry("ghostunnel")
	_ = LiveMetrics(r)
	r.StartRuntimeCollector(time.Hour)

	var buf bytes.Buffer
	r.writeGraphite(&buf, 1700000000)
	assert.Contains(t, buf.String(), "ghostunnel.runtime.goroutines.value ",
		"a gauge must render with the .value suffix")
}

func TestStartRuntimeCollectorIdempotentAndTracksGC(t *testing.T) {
	// Ensure at least one GC has happened so collectOnce's pause-feeding loop runs.
	runtime.GC()
	runtime.GC()

	r := NewRegistry("ghostunnel")
	_ = LiveMetrics(r)
	r.StartRuntimeCollector(time.Hour)
	first := r.runtime

	// A second call must be a no-op (no re-registration panic, same collector).
	r.StartRuntimeCollector(time.Hour)
	assert.Same(t, first, r.runtime, "second StartRuntimeCollector must be a no-op")

	// The synchronous initial collect fed the observed GC pauses into the timer.
	c, ok := r.TimerCount("runtime.mem.gc.duration")
	require.True(t, ok)
	assert.Positive(t, c, "GC pause durations must be recorded after GCs have occurred")
}

// renderProm renders the native Prometheus text exposition for r.
func renderProm(t *testing.T, r *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_metrics/prometheus", nil)
	r.PrometheusHandler().ServeHTTP(rec, req)
	return rec.Body.String()
}
