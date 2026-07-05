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
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// runtimeCollector reproduces go-sq-metrics' collectMetrics: a fixed set of
// runtime/GC gauges plus a GC-pause histogram (an internal timer, so it expands
// to the same count/mean/percentile fields on the legacy sinks). The gauges are
// persistent prometheus instruments updated on an interval, so they also appear
// on the native Prometheus endpoint exactly like Ghostunnel's other metrics.
//
// Note: Ghostunnel's go_*/process_* collectors already export the canonical
// Prometheus runtime/process metrics. These ghostunnel.runtime.* gauges are
// retained because they are part of the established JSON and Graphite contract.
type runtimeCollector struct {
	gauges     []runtimeGauge
	gcDuration *timer

	observedPauses uint32
}

// runtimeGauge binds a gauge to the function that reads its current value.
// goroutines/cgo-calls ignore the MemStats argument; the rest read from it.
type runtimeGauge struct {
	gauge prometheus.Gauge
	read  func(*runtime.MemStats) float64
}

// registerRuntime installs the runtime collector's instruments on r. The gauges
// are declared as a name→reader map; iteration order is irrelevant since the
// legacy adapters do not depend on registration order.
func (r *Registry) registerRuntime() *runtimeCollector {
	readers := map[string]func(*runtime.MemStats) float64{
		"runtime.mem.alloc":       func(m *runtime.MemStats) float64 { return float64(m.Alloc) },
		"runtime.mem.total-alloc": func(m *runtime.MemStats) float64 { return float64(m.TotalAlloc) },
		"runtime.mem.sys":         func(m *runtime.MemStats) float64 { return float64(m.Sys) },
		"runtime.mem.lookups":     func(m *runtime.MemStats) float64 { return float64(m.Lookups) },
		"runtime.mem.mallocs":     func(m *runtime.MemStats) float64 { return float64(m.Mallocs) },
		"runtime.mem.frees":       func(m *runtime.MemStats) float64 { return float64(m.Frees) },

		"runtime.mem.heap.alloc":    func(m *runtime.MemStats) float64 { return float64(m.HeapAlloc) },
		"runtime.mem.heap.sys":      func(m *runtime.MemStats) float64 { return float64(m.HeapSys) },
		"runtime.mem.heap.idle":     func(m *runtime.MemStats) float64 { return float64(m.HeapIdle) },
		"runtime.mem.heap.inuse":    func(m *runtime.MemStats) float64 { return float64(m.HeapInuse) },
		"runtime.mem.heap.released": func(m *runtime.MemStats) float64 { return float64(m.HeapReleased) },
		"runtime.mem.heap.objects":  func(m *runtime.MemStats) float64 { return float64(m.HeapObjects) },

		"runtime.mem.stack.inuse": func(m *runtime.MemStats) float64 { return float64(m.StackInuse) },
		"runtime.mem.stack.sys":   func(m *runtime.MemStats) float64 { return float64(m.StackSys) },

		"runtime.goroutines": func(*runtime.MemStats) float64 { return float64(runtime.NumGoroutine()) },
		"runtime.cgo-calls":  func(*runtime.MemStats) float64 { return float64(runtime.NumCgoCall()) },

		"runtime.mem.gc.num-gc":       func(m *runtime.MemStats) float64 { return float64(m.NumGC) },
		"runtime.mem.gc.cpu-fraction": func(m *runtime.MemStats) float64 { return m.GCCPUFraction },
	}

	rc := &runtimeCollector{}
	for dotted, read := range readers {
		rc.gauges = append(rc.gauges, runtimeGauge{gauge: r.registerGauge(dotted), read: read})
	}
	rc.gcDuration = r.registerTimer("runtime.mem.gc.duration", shortDurationBuckets)

	return rc
}

// collectOnce reads the current runtime/GC statistics into the gauges and feeds
// any GC pauses observed since the last call into the GC-duration timer. This
// mirrors one iteration of go-sq-metrics' collectMetrics loop.
func (rc *runtimeCollector) collectOnce() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	for _, g := range rc.gauges {
		g.gauge.Set(g.read(&mem))
	}

	// Feed each not-yet-observed GC pause into the duration timer. PauseNs is a
	// 256-entry circular buffer of the most recent pauses; we only catch up the
	// most recent 256 if we have fallen behind.
	start := rc.observedPauses
	if mem.NumGC-start > 256 {
		start = mem.NumGC - 256
	}
	for i := start; i < mem.NumGC; i++ {
		rc.gcDuration.observeNanos(int64(mem.PauseNs[i%256]))
	}
	rc.observedPauses = mem.NumGC
}

// StartRuntimeCollector registers the runtime gauges (once) and starts a
// background goroutine that refreshes them every interval. An initial
// collection runs synchronously so the gauges are populated before the first
// scrape or push. Concurrent and repeated calls are safe: only the first call
// registers and starts anything (guarded by a sync.Once, since racing
// registrations would panic in MustRegister). The interval of any later call
// is ignored.
//
// The goroutine runs for the remaining lifetime of the process by design:
// Ghostunnel starts the collector once at startup and never tears it down
// before exit, so there is deliberately no stop mechanism.
func (r *Registry) StartRuntimeCollector(interval time.Duration) {
	r.runtimeOnce.Do(func() {
		rc := r.registerRuntime()
		r.runtime = rc
		rc.collectOnce()

		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for range ticker.C {
				rc.collectOnce()
			}
		}()
	})
}
