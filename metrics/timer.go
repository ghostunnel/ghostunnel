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
	"math"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// timer is the only non-trivial instrument. A prometheus.Summary feeds the
// {50,75,95,99}-percentile fields (and the native Prometheus _sum/_count and
// quantiles); the min/max atomics carry the two statistics the Summary does not
// expose so the JSON and Graphite adapters can keep emitting them.
//
// Observations are recorded in nanoseconds, matching the units go-metrics
// timers historically reported through every sink. There is deliberately no
// EWMA or variance: the derived rate/std-dev/variance fields were dropped in
// this migration, which is what keeps this type simple.
type timer struct {
	summary prometheus.Summary
	minNs   atomic.Int64
	maxNs   atomic.Int64
}

func newTimer(s prometheus.Summary) *timer {
	t := &timer{summary: s}
	// Start min at the maximum so the first observation always wins the CAS.
	// snapshot() never reads minNs until count > 0, so this sentinel is never
	// observed.
	t.minNs.Store(math.MaxInt64)
	return t
}

// UpdateSince records the elapsed time since start. It is called on the
// connection hot path, so it does only the minimum: one Summary observation
// (mutex-guarded inside client_golang) plus two compare-and-swap loops for
// min/max. The Summary itself maintains the cumulative count and sum the
// adapters read back.
func (t *timer) UpdateSince(start time.Time) {
	t.observeNanos(time.Since(start).Nanoseconds())
}

// observeNanos records a single observation given directly in nanoseconds. It
// is used both by UpdateSince and by the runtime collector's GC-pause path,
// which has a pause duration rather than a start time.
//
// The min/max atomics are updated *before* the Summary observation so a reader
// can never gather a non-zero sample count while min still holds its sentinel
// (which would otherwise surface MaxInt64 as a one-shot ".min" on a timer's
// very first observation). snapshot() reads count from the Summary, so by the
// time count reflects this observation, min/max already do too.
func (t *timer) observeNanos(d int64) {
	for {
		cur := t.minNs.Load()
		if d >= cur || t.minNs.CompareAndSwap(cur, d) {
			break
		}
	}
	for {
		cur := t.maxNs.Load()
		if d <= cur || t.maxNs.CompareAndSwap(cur, d) {
			break
		}
	}

	t.summary.Observe(float64(d))
}
