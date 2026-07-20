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

// Package metrics is Ghostunnel's single metrics backend. It owns one
// *prometheus.Registry and exposes the instrument handles the connection hot
// path updates, plus the three export sinks (JSON, Graphite, native
// Prometheus) built directly on top of that registry.
//
// It exists to keep the prometheus/client_golang dependency out of the proxy
// package and to give the two legacy wire-format adapters (JSON and Graphite)
// a single, in-repo source of truth. There is exactly one implementation; this
// is encapsulation, not a pluggable-backend abstraction.
//
// The metric names (e.g. conn.open, conn.handshake) are part of Ghostunnel's
// exported surface and must not change. See docs/networking/metrics.md.
package metrics

import (
	"math"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// Counter is the hot-path counter handle. Dec is only meaningful for the
// gauge-like conn.open metric; on a monotonic counter it is a no-op.
type Counter interface {
	Inc(int64)
	Dec(int64)
}

// Timer records a duration measured from a start time.
type Timer interface {
	UpdateSince(time.Time)
}

// Metrics holds the instrument handles updated on the connection hot path.
// Injecting the handles (instead of reading package globals) lets the caller
// decide, once at startup, whether to collect at all: pass LiveMetrics to
// record against a registry, or NilMetrics to make every update a no-op when no
// metrics sink is configured. The metric names are part of Ghostunnel's
// exported surface and must not change.
type Metrics struct {
	OpenCounter             Counter // conn.open (gauge-like: Inc/Dec)
	ConnTimeoutCounter      Counter // conn.timeout
	ConnErrorCounter        Counter // conn.error
	TotalCounter            Counter // accept.total
	SuccessCounter          Counter // accept.success
	ErrorCounter            Counter // accept.error
	HandshakeTimeoutCounter Counter // accept.timeout
	HandshakeTimer          Timer   // conn.handshake
	ConnTimer               Timer   // conn.lifetime
}

// Duration histogram bucket boundaries, in nanoseconds. Two presets cover the
// two operational scales Ghostunnel times: short for sub-second events (TLS
// handshakes and GC pauses) and long for connection lifetimes, which can run to
// hours. The classic le-buckets serve both classic Prometheus scrapers and the
// JSON/Graphite percentile interpolation (see histogramQuantile); the native
// Prometheus endpoint additionally auto-scales via nativeHistogramBucketFactor,
// so the choice of classic layout only bounds the accuracy of the legacy
// percentile estimates, not the native histogram.
var (
	shortDurationBuckets = prometheus.ExponentialBucketsRange(1e4, 1e10, 24)    // 10µs … 10s
	longDurationBuckets  = prometheus.ExponentialBucketsRange(1e6, 8.64e13, 30) // 1ms … 24h
)

// Native (exponential) histogram tuning. nativeHistogramBucketFactor enables
// the native representation on every timer, so modern Prometheus scrapers get an
// auto-scaling histogram regardless of the classic bucket layout above.
//
// conn.lifetime durations are driven by external input (connections can live
// from microseconds to hours), so the native bucket count is capped and the
// schema is periodically reset to keep memory bounded, as client_golang
// recommends for externally-influenced observations.
const (
	nativeHistogramBucketFactor     = 1.1
	nativeHistogramMaxBucketNumber  = 160
	nativeHistogramMinResetDuration = time.Hour
)

// legacyKind selects how a single-valued metric is rendered by the legacy
// (JSON/Graphite) adapters. It is independent of the underlying Prometheus
// instrument type: conn.open is a prometheus.Gauge internally (so it can be
// decremented) but is rendered as a counter (".count") to preserve its
// historical Graphite output.
type legacyKind int

const (
	kindCounter legacyKind = iota // Graphite ".count"
	kindGauge                     // Graphite ".value"
	kindTimer                     // expanded to count/mean/percentiles
)

// descriptor records everything the adapters need about one registered metric:
// its dotted legacy name, the flattened Prometheus family name used to look its
// value up in a Gather(), and how to render it. Timers carry no extra handle:
// count/sum and the classic buckets the percentiles interpolate from all come
// straight out of the gathered histogram.
type descriptor struct {
	dotted   string // e.g. "conn.open", "runtime.mem.alloc"
	promName string // e.g. "ghostunnel_conn_open" (as gathered)
	kind     legacyKind
}

// Registry owns the single prometheus.Registry plus the metadata the legacy
// adapters need to translate it back into Ghostunnel's dotted wire formats.
type Registry struct {
	prom      *prometheus.Registry
	prefix    string // raw, prepended to dotted names (JSON/Graphite)
	namespace string // flattened prefix, used as the Prometheus namespace
	hostname  string

	mu          sync.Mutex
	descriptors []*descriptor

	// runtimeOnce guards runtime's registration: r.mu cannot be held across
	// registerRuntime (it takes r.mu per instrument), and unguarded racing
	// calls would panic in MustRegister.
	runtimeOnce sync.Once
	runtime     *runtimeCollector
}

// osHostname is a test seam for os.Hostname, which cannot be made to fail on
// demand in a test.
var osHostname = os.Hostname

// NewRegistry creates an empty registry with the default Go and process
// collectors registered (so go_*/process_* appear on the native Prometheus
// endpoint, exactly as the deathowl bridge produced them on the default
// registerer). The prefix is Ghostunnel's --metrics-prefix.
func NewRegistry(prefix string) *Registry {
	prom := prometheus.NewRegistry()
	prom.MustRegister(collectors.NewGoCollector())
	prom.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	hostname, err := osHostname()
	if err != nil {
		// The hostname only decorates JSON metrics entries; a placeholder
		// beats refusing to start (go-sq-metrics historically panicked here).
		hostname = "unknown"
	}

	return &Registry{
		prom:      prom,
		prefix:    prefix,
		namespace: flatten(prefix),
		hostname:  hostname,
	}
}

// PrometheusHandler returns the native Prometheus exposition handler for this
// registry, used to serve /_metrics/prometheus.
func (r *Registry) PrometheusHandler() http.Handler {
	return promhttp.HandlerFor(r.prom, promhttp.HandlerOpts{})
}

// LiveMetrics registers the nine connection metrics under their canonical
// names on r and returns handles that record to them. It must be called at
// most once per registry.
func LiveMetrics(r *Registry) *Metrics {
	return &Metrics{
		OpenCounter:             r.registerOpenGauge("conn.open"),
		ConnTimeoutCounter:      r.registerCounter("conn.timeout"),
		ConnErrorCounter:        r.registerCounter("conn.error"),
		TotalCounter:            r.registerCounter("accept.total"),
		SuccessCounter:          r.registerCounter("accept.success"),
		ErrorCounter:            r.registerCounter("accept.error"),
		HandshakeTimeoutCounter: r.registerCounter("accept.timeout"),
		HandshakeTimer:          r.registerTimer("conn.handshake", shortDurationBuckets),
		ConnTimer:               r.registerTimer("conn.lifetime", longDurationBuckets),
	}
}

// NilMetrics returns handles whose updates are all no-ops. Use it when no
// metrics sink is configured so the connection hot path spends nothing updating
// instruments that nothing will ever observe.
func NilMetrics() *Metrics {
	return &Metrics{
		OpenCounter:             nopCounter{},
		ConnTimeoutCounter:      nopCounter{},
		ConnErrorCounter:        nopCounter{},
		TotalCounter:            nopCounter{},
		SuccessCounter:          nopCounter{},
		ErrorCounter:            nopCounter{},
		HandshakeTimeoutCounter: nopCounter{},
		HandshakeTimer:          nopTimer{},
		ConnTimer:               nopTimer{},
	}
}

// registerCounter registers a monotonic prometheus.Counter, always rendered as a
// Graphite ".count", and records its descriptor.
func (r *Registry) registerCounter(dotted string) Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: r.namespace,
		Name:      flatten(dotted),
		Help:      dotted,
	})
	r.prom.MustRegister(c)
	r.addDescriptor(&descriptor{dotted: dotted, promName: fqName(r.namespace, dotted), kind: kindCounter})
	return promCounter{c}
}

// newGauge registers a prometheus.Gauge under dotted with the given legacy
// rendering kind and returns the raw instrument so the caller can Set it.
func (r *Registry) newGauge(dotted string, kind legacyKind) prometheus.Gauge {
	g := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: r.namespace,
		Name:      flatten(dotted),
		Help:      dotted,
	})
	r.prom.MustRegister(g)
	r.addDescriptor(&descriptor{dotted: dotted, promName: fqName(r.namespace, dotted), kind: kind})
	return g
}

// registerGauge registers a gauge rendered as a gauge (".value").
func (r *Registry) registerGauge(dotted string) prometheus.Gauge {
	return r.newGauge(dotted, kindGauge)
}

// registerOpenGauge registers conn.open: a gauge (so it can be decremented)
// rendered as a counter (".count") to preserve its historical single-value
// output.
func (r *Registry) registerOpenGauge(dotted string) Counter {
	return promGauge{r.newGauge(dotted, kindCounter)}
}

// registerTimer registers a prometheus.Histogram (with the given classic
// bucket layout plus the native-histogram representation) and the internal
// timer that records into it.
func (r *Registry) registerTimer(dotted string, buckets []float64) *timer {
	h := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:                       r.namespace,
		Name:                            flatten(dotted),
		Help:                            dotted,
		Buckets:                         buckets,
		NativeHistogramBucketFactor:     nativeHistogramBucketFactor,
		NativeHistogramMaxBucketNumber:  nativeHistogramMaxBucketNumber,
		NativeHistogramMinResetDuration: nativeHistogramMinResetDuration,
	})
	r.prom.MustRegister(h)
	t := newTimer(h)
	r.addDescriptor(&descriptor{dotted: dotted, promName: fqName(r.namespace, dotted), kind: kindTimer})
	return t
}

func (r *Registry) addDescriptor(d *descriptor) {
	r.mu.Lock()
	r.descriptors = append(r.descriptors, d)
	r.mu.Unlock()
}

// single is a counter/gauge reading in the normalized snapshot. The value is
// always carried as the float64 Prometheus gathers; the adapters render it
// directly (Go marshals an integer-valued float64 without a decimal point, so
// counters encode as plain integers in JSON).
type single struct {
	dotted string
	kind   legacyKind
	value  float64
}

// timerReading is a timer/histogram reading in the normalized snapshot, in
// nanoseconds (matching go-metrics' historical units). min/max were dropped in
// the histogram migration; percentiles are interpolated from the histogram
// buckets (see histogramQuantile).
type timerReading struct {
	dotted             string
	count              int64
	mean               float64
	p50, p75, p95, p99 float64
}

// snap is the normalized intermediate both legacy adapters format.
type snap struct {
	singles []single
	timers  []timerReading
}

// snapshot reads every registered metric once, in canonical descriptor order.
// Counter/gauge/histogram values all come from a single Gather() of the
// prometheus registry. Interpolated percentiles for an empty timer are NaN;
// nz() clamps NaN/Inf to zero so the JSON encoder never fails and Graphite
// never emits "NaN".
func (r *Registry) snapshot() snap {
	families, _ := r.prom.Gather()
	byName := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		byName[f.GetName()] = f
	}

	r.mu.Lock()
	descriptors := r.descriptors
	r.mu.Unlock()

	var s snap
	for _, d := range descriptors {
		fam := byName[d.promName]
		if d.kind == kindTimer {
			s.timers = append(s.timers, readTimer(d, fam))
			continue
		}
		s.singles = append(s.singles, readSingle(d, fam))
	}
	return s
}

func readSingle(d *descriptor, fam *dto.MetricFamily) single {
	v := single{dotted: d.dotted, kind: d.kind}
	if fam == nil || len(fam.GetMetric()) == 0 {
		return v
	}
	m0 := fam.GetMetric()[0]
	switch fam.GetType() {
	case dto.MetricType_COUNTER:
		v.value = m0.GetCounter().GetValue()
	case dto.MetricType_GAUGE:
		v.value = m0.GetGauge().GetValue()
	}
	return v
}

func readTimer(d *descriptor, fam *dto.MetricFamily) timerReading {
	tr := timerReading{dotted: d.dotted}
	if fam == nil || len(fam.GetMetric()) == 0 {
		return tr
	}
	h := fam.GetMetric()[0].GetHistogram()
	count := h.GetSampleCount()
	tr.count = int64(count)
	if count == 0 {
		return tr
	}
	tr.mean = nz(h.GetSampleSum() / float64(count))
	buckets := h.GetBucket()
	tr.p50 = nz(histogramQuantile(0.5, buckets, count))
	tr.p75 = nz(histogramQuantile(0.75, buckets, count))
	tr.p95 = nz(histogramQuantile(0.95, buckets, count))
	tr.p99 = nz(histogramQuantile(0.99, buckets, count))
	return tr
}

// histogramQuantile estimates the q-quantile (0 < q < 1) of a classic
// Prometheus histogram by linear interpolation within the bucket the rank falls
// into, mirroring PromQL's histogram_quantile. It preserves the JSON/Graphite
// percentile fields now that timers are histograms rather than summaries.
//
// buckets are the cumulative le-buckets as gathered; count is the total
// observation count. All Ghostunnel timer observations are non-negative
// durations, so the lowest bucket is interpolated from a zero lower bound.
// Returns 0 for an empty histogram. A rank that falls in the implicit +Inf
// bucket (i.e. above the highest finite boundary) is reported at that highest
// finite boundary, since there is no upper edge to interpolate toward — this
// caps very-large observations at the top of the configured bucket range.
func histogramQuantile(q float64, buckets []*dto.Bucket, count uint64) float64 {
	if count == 0 || len(buckets) == 0 {
		return 0
	}

	type cumBucket struct {
		upper float64
		cum   float64
	}
	bs := make([]cumBucket, 0, len(buckets)+1)
	for _, b := range buckets {
		bs = append(bs, cumBucket{upper: b.GetUpperBound(), cum: float64(b.GetCumulativeCount())})
	}
	sort.Slice(bs, func(i, j int) bool { return bs[i].upper < bs[j].upper })

	// client_golang omits the +Inf bucket from the gathered list; the total
	// lives in SampleCount. Append it so the highest rank has a bucket to land
	// in.
	if !math.IsInf(bs[len(bs)-1].upper, +1) {
		bs = append(bs, cumBucket{upper: math.Inf(+1), cum: float64(count)})
	}

	rank := q * float64(count)
	i := sort.Search(len(bs), func(i int) bool { return bs[i].cum >= rank })
	if i == len(bs) {
		i = len(bs) - 1
	}

	if math.IsInf(bs[i].upper, +1) {
		// Rank lands in the +Inf bucket: report the highest finite boundary.
		if i == 0 {
			return 0
		}
		return bs[i-1].upper
	}

	bucketEnd := bs[i].upper
	bucketStart, cumPrev := 0.0, 0.0
	if i > 0 {
		bucketStart = bs[i-1].upper
		cumPrev = bs[i-1].cum
	}
	countInBucket := bs[i].cum - cumPrev
	if countInBucket <= 0 {
		return bucketEnd
	}
	return bucketStart + (bucketEnd-bucketStart)*((rank-cumPrev)/countInBucket)
}

// SingleValue reports the current value of a counter/gauge by its dotted name.
// Intended for tests and internal assertions.
func (r *Registry) SingleValue(dotted string) (int64, bool) {
	for _, sg := range r.snapshot().singles {
		if sg.dotted == dotted {
			return int64(sg.value), true
		}
	}
	return 0, false
}

// TimerCount reports the number of observations recorded by a timer by its
// dotted name. Intended for tests and internal assertions.
func (r *Registry) TimerCount(dotted string) (int64, bool) {
	for _, t := range r.snapshot().timers {
		if t.dotted == dotted {
			return t.count, true
		}
	}
	return 0, false
}

// promCounter adapts a monotonic prometheus.Counter to the Counter interface.
// Dec is a no-op: Prometheus counters cannot decrease, and none of Ghostunnel's
// real counters are ever decremented.
type promCounter struct{ c prometheus.Counter }

func (p promCounter) Inc(n int64) { p.c.Add(float64(n)) }
func (p promCounter) Dec(int64)   {}

// promGauge adapts a prometheus.Gauge to the Counter interface so conn.open can
// be both incremented and decremented while presenting a single value.
type promGauge struct{ g prometheus.Gauge }

func (p promGauge) Inc(n int64) { p.g.Add(float64(n)) }
func (p promGauge) Dec(n int64) { p.g.Sub(float64(n)) }

// nopCounter / nopTimer are the no-op handles returned by NilMetrics.
type nopCounter struct{}

func (nopCounter) Inc(int64) {}
func (nopCounter) Dec(int64) {}

type nopTimer struct{}

func (nopTimer) UpdateSince(time.Time) {}

// flatten maps a dotted/dashed metric name to a Prometheus-legal name,
// reproducing the deathowl bridge's flattenKey so existing Prometheus names are
// preserved.
func flatten(s string) string {
	return flattenReplacer.Replace(s)
}

var flattenReplacer = strings.NewReplacer(" ", "_", ".", "_", "-", "_", "=", "_", "/", "_")

// fqName builds the fully-qualified Prometheus family name (namespace + flattened
// metric name) that Gather() reports, matching how the instruments are registered.
func fqName(namespace, dotted string) string {
	return prometheus.BuildFQName(namespace, "", flatten(dotted))
}

// nz clamps NaN/Inf to zero.
func nz(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return f
}
