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
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// timer wraps a prometheus.Histogram to record durations in nanoseconds. The
// histogram carries the cumulative _count/_sum and the classic le-buckets that
// the JSON and Graphite adapters interpolate percentiles from; the native
// Prometheus endpoint additionally exposes it as a native (exponential)
// histogram for scrapers that negotiate it.
//
// There is deliberately no min/max, EWMA, std-dev, or variance: those derived
// fields were dropped in the histogram migration, which is what keeps this type
// a thin wrapper. Percentiles are a query-time concern on Prometheus
// (histogram_quantile) and are bucket-interpolated for the legacy sinks (see
// histogramQuantile in metrics.go).
//
// Observations are recorded in nanoseconds, matching the units go-metrics
// timers historically reported through every sink.
type timer struct {
	hist prometheus.Histogram
}

func newTimer(h prometheus.Histogram) *timer {
	return &timer{hist: h}
}

// UpdateSince records the elapsed time since start. It is called on the
// connection hot path, so it does the minimum: a single histogram observation
// (a bucket search plus atomic increments inside client_golang).
func (t *timer) UpdateSince(start time.Time) {
	t.observeNanos(time.Since(start).Nanoseconds())
}

// observeNanos records a single observation given directly in nanoseconds. It
// is used both by UpdateSince and by the runtime collector's GC-pause path,
// which has a pause duration rather than a start time.
func (t *timer) observeNanos(d int64) {
	t.hist.Observe(float64(d))
}
