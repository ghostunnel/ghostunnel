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
// runtime/GC gauges plus a GC-pause "histogram" (modeled here as an internal
// timer so it expands to the same count/min/max/mean/percentile fields). The
// gauges are persistent prometheus instruments updated on an interval, so they
// also appear on the native Prometheus endpoint exactly like Ghostunnel's other
// metrics.
//
// Note: Ghostunnel's go_*/process_* collectors already export the canonical
// Prometheus runtime/process metrics. These ghostunnel.runtime.* gauges are
// retained because they are part of the established JSON and Graphite contract.
type runtimeCollector struct {
	memGauges   []memGauge
	goroutines  prometheus.Gauge
	cgoCalls    prometheus.Gauge
	numGC       prometheus.Gauge
	cpuFraction prometheus.Gauge
	gcDuration  *timer

	observedPauses uint32
}

// memGauge binds a runtime.MemStats field reader to its gauge.
type memGauge struct {
	gauge prometheus.Gauge
	read  func(*runtime.MemStats) uint64
}

// registerRuntime installs the runtime collector's instruments on r in their
// canonical order. The order is fixed (not map iteration) so the JSON/Graphite
// output is deterministic.
func (r *Registry) registerRuntime() *runtimeCollector {
	rc := &runtimeCollector{}

	add := func(dotted string, read func(*runtime.MemStats) uint64) {
		rc.memGauges = append(rc.memGauges, memGauge{gauge: r.registerGauge(dotted, false), read: read})
	}

	add("runtime.mem.alloc", func(m *runtime.MemStats) uint64 { return m.Alloc })
	add("runtime.mem.total-alloc", func(m *runtime.MemStats) uint64 { return m.TotalAlloc })
	add("runtime.mem.sys", func(m *runtime.MemStats) uint64 { return m.Sys })
	add("runtime.mem.lookups", func(m *runtime.MemStats) uint64 { return m.Lookups })
	add("runtime.mem.mallocs", func(m *runtime.MemStats) uint64 { return m.Mallocs })
	add("runtime.mem.frees", func(m *runtime.MemStats) uint64 { return m.Frees })

	add("runtime.mem.heap.alloc", func(m *runtime.MemStats) uint64 { return m.HeapAlloc })
	add("runtime.mem.heap.sys", func(m *runtime.MemStats) uint64 { return m.HeapSys })
	add("runtime.mem.heap.idle", func(m *runtime.MemStats) uint64 { return m.HeapIdle })
	add("runtime.mem.heap.inuse", func(m *runtime.MemStats) uint64 { return m.HeapInuse })
	add("runtime.mem.heap.released", func(m *runtime.MemStats) uint64 { return m.HeapReleased })
	add("runtime.mem.heap.objects", func(m *runtime.MemStats) uint64 { return m.HeapObjects })

	add("runtime.mem.stack.inuse", func(m *runtime.MemStats) uint64 { return m.StackInuse })
	add("runtime.mem.stack.sys", func(m *runtime.MemStats) uint64 { return m.StackSys })

	rc.goroutines = r.registerGauge("runtime.goroutines", false)
	rc.cgoCalls = r.registerGauge("runtime.cgo-calls", false)

	rc.numGC = r.registerGauge("runtime.mem.gc.num-gc", false)
	rc.cpuFraction = r.registerGauge("runtime.mem.gc.cpu-fraction", true)
	rc.gcDuration = r.registerTimer("runtime.mem.gc.duration")

	return rc
}

// collectOnce reads the current runtime/GC statistics into the gauges and feeds
// any GC pauses observed since the last call into the GC-duration timer. This
// mirrors one iteration of go-sq-metrics' collectMetrics loop.
func (rc *runtimeCollector) collectOnce() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	for _, mg := range rc.memGauges {
		mg.gauge.Set(float64(mg.read(&mem)))
	}
	rc.goroutines.Set(float64(runtime.NumGoroutine()))
	rc.cgoCalls.Set(float64(runtime.NumCgoCall()))
	rc.numGC.Set(float64(mem.NumGC))
	rc.cpuFraction.Set(mem.GCCPUFraction)

	// Feed each not-yet-observed GC pause into the duration timer. PauseNs is a
	// 256-entry circular buffer of the most recent pauses; we only catch up the
	// most recent 256 if we have fallen behind.
	start := rc.observedPauses
	if mem.NumGC-start > 256 {
		start = mem.NumGC - 256
	}
	for i := start; i < mem.NumGC; i++ {
		rc.gcDuration.observeNanos(int64(mem.PauseNs[(i+1)%256]))
	}
	rc.observedPauses = mem.NumGC
}

// StartRuntimeCollector registers the runtime gauges (once) and starts a
// background goroutine that refreshes them every interval. An initial
// collection runs synchronously so the gauges are populated before the first
// scrape or push. It is safe to call at most once per registry.
func (r *Registry) StartRuntimeCollector(interval time.Duration) {
	if r.runtime != nil {
		return
	}
	r.runtime = r.registerRuntime()
	r.runtime.collectOnce()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			r.runtime.collectOnce()
		}
	}()
}
