/*-
 * Copyright 2016 Square Inc.
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

package sqmetrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/rcrowley/go-metrics"
)

// SquareMetrics posts metrics to an HTTP/JSON bridge endpoint
type SquareMetrics struct {
	registry metrics.Registry
	url      string
	prefix   string
	hostname string
	interval time.Duration
	logger   *log.Logger
	client   *http.Client
}

// NewMetrics is the entry point for this code
func NewMetrics(metricsURL, metricsPrefix string, client *http.Client, interval time.Duration, registry metrics.Registry, logger *log.Logger) *SquareMetrics {
	hostname, err := os.Hostname()
	if err != nil {
		panic(err)
	}

	metrics := &SquareMetrics{
		registry: registry,
		url:      metricsURL,
		prefix:   metricsPrefix,
		hostname: hostname,
		interval: interval,
		logger:   logger,
		client:   client,
	}

	if metricsURL != "" {
		go metrics.publishMetrics()
	}

	go metrics.collectSystemMetrics()
	return metrics
}

func (mb *SquareMetrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics := mb.SerializeMetrics()
	raw, err := json.Marshal(metrics)
	if err != nil {
		panic(err)
	}
	w.Write(raw)
}

// Publish metrics to bridge
func (mb *SquareMetrics) publishMetrics() {
	for range time.Tick(mb.interval) {
		err := mb.postMetrics()
		if err != nil {
			mb.logger.Printf("error reporting metrics: %s", err)
		}
	}
}

// Collect memory usage metrics
func (mb *SquareMetrics) collectSystemMetrics() {
	var mem runtime.MemStats

	update := func(name string, value uint64) {
		metrics.GetOrRegisterGauge(name, mb.registry).Update(int64(value))
	}

	updateFloat := func(name string, value float64) {
		metrics.GetOrRegisterGaugeFloat64(name, mb.registry).Update(value)
	}

	sample := metrics.NewExpDecaySample(1028, 0.015)
	gcHistogram := metrics.GetOrRegisterHistogram("runtime.mem.gc.duration", mb.registry, sample)

	var observedPauses uint32
	for range time.Tick(mb.interval) {
		runtime.ReadMemStats(&mem)

		update("runtime.mem.alloc", mem.Alloc)
		update("runtime.mem.total-alloc", mem.TotalAlloc)
		update("runtime.mem.sys", mem.Sys)
		update("runtime.mem.lookups", mem.Lookups)
		update("runtime.mem.mallocs", mem.Mallocs)
		update("runtime.mem.frees", mem.Frees)

		update("runtime.mem.heap.alloc", mem.HeapAlloc)
		update("runtime.mem.heap.sys", mem.HeapSys)
		update("runtime.mem.heap.idle", mem.HeapIdle)
		update("runtime.mem.heap.inuse", mem.HeapInuse)
		update("runtime.mem.heap.released", mem.HeapReleased)
		update("runtime.mem.heap.objects", mem.HeapObjects)

		update("runtime.mem.stack.inuse", mem.StackInuse)
		update("runtime.mem.stack.sys", mem.StackSys)

		update("runtime.goroutines", uint64(runtime.NumGoroutine()))
		update("runtime.cgo-calls", uint64(runtime.NumCgoCall()))

		update("runtime.mem.gc.num-gc", uint64(mem.NumGC))
		updateFloat("runtime.mem.gc.cpu-fraction", mem.GCCPUFraction)

		// Update histogram of GC pauses
		for ; observedPauses < mem.NumGC; observedPauses++ {
			gcHistogram.Update(int64(mem.PauseNs[(observedPauses+1)%256]))
		}
	}
}

func (mb *SquareMetrics) postMetrics() error {
	metrics := mb.SerializeMetrics()
	raw, err := json.Marshal(metrics)
	if err != nil {
		panic(err)
	}
	resp, err := mb.client.Post(mb.url, "application/json", bytes.NewReader(raw))
	if resp != nil {
		defer resp.Body.Close()
	}
	return err
}

func (mb *SquareMetrics) serializeMetric(now int64, metric tuple) map[string]interface{} {
	return map[string]interface{}{
		"timestamp": now,
		"metric":    fmt.Sprintf("%s.%s", mb.prefix, metric.name),
		"value":     metric.value,
		"hostname":  mb.hostname,
	}
}

type tuple struct {
	name  string
	value interface{}
}

// SerializeMetrics returns a map of the collected metrics, suitable for JSON marshalling
func (mb *SquareMetrics) SerializeMetrics() []map[string]interface{} {
	nvs := []tuple{}

	mb.registry.Each(func(name string, i interface{}) {
		switch metric := i.(type) {
		case metrics.Counter:
			nvs = append(nvs, tuple{name, metric.Count()})
		case metrics.Gauge:
			nvs = append(nvs, tuple{name, metric.Value()})
		case metrics.GaugeFloat64:
			nvs = append(nvs, tuple{name, metric.Value()})
		case metrics.Histogram:
			histogram := metric.Snapshot()
			nvs = append(nvs, []tuple{
				{fmt.Sprintf("%s.count", name), histogram.Count()},
				{fmt.Sprintf("%s.min", name), histogram.Min()},
				{fmt.Sprintf("%s.max", name), histogram.Max()},
				{fmt.Sprintf("%s.mean", name), histogram.Mean()},
				{fmt.Sprintf("%s.50-percentile", name), histogram.Percentile(0.5)},
				{fmt.Sprintf("%s.75-percentile", name), histogram.Percentile(0.75)},
				{fmt.Sprintf("%s.95-percentile", name), histogram.Percentile(0.95)},
				{fmt.Sprintf("%s.99-percentile", name), histogram.Percentile(0.99)},
			}...)
		case metrics.Timer:
			timer := metric.Snapshot()
			nvs = append(nvs, []tuple{
				{fmt.Sprintf("%s.count", name), timer.Count()},
				{fmt.Sprintf("%s.min", name), timer.Min()},
				{fmt.Sprintf("%s.max", name), timer.Max()},
				{fmt.Sprintf("%s.mean", name), timer.Mean()},
				{fmt.Sprintf("%s.50-percentile", name), timer.Percentile(0.5)},
				{fmt.Sprintf("%s.75-percentile", name), timer.Percentile(0.75)},
				{fmt.Sprintf("%s.95-percentile", name), timer.Percentile(0.95)},
				{fmt.Sprintf("%s.99-percentile", name), timer.Percentile(0.99)},
			}...)
		}
	})

	now := time.Now().Unix()
	out := []map[string]interface{}{}
	for _, nv := range nvs {
		out = append(out, mb.serializeMetric(now, nv))
	}

	return out
}
