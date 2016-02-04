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

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rcrowley/go-metrics"
)

// Metrics bridge posts metrics to an HTTP/JSON bridge endpoint
type metricsConfig struct {
	url      string
	registry metrics.Registry
	prefix   string
	hostname string
}

func (mb *metricsConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	metrics := mb.serializeMetrics()
	raw, err := json.Marshal(metrics)
	if err != nil {
		logger.Printf("%s", err)
	}
	w.Write(raw)
}

// Publish metrics to bridge
func (mb *metricsConfig) publishMetrics() {
	for _ = range time.Tick(1 * time.Second) {
		mb.postMetrics()
	}
}

func (mb *metricsConfig) postMetrics() {
	metrics := mb.serializeMetrics()
	raw, err := json.Marshal(metrics)
	if err != nil {
		logger.Printf("%s", err)
	}
	http.Post(mb.url, "application/json", bytes.NewReader(raw))
}

func (mb *metricsConfig) serializeMetric(now int64, metric tuple) map[string]interface{} {
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

func (mb *metricsConfig) serializeMetrics() []map[string]interface{} {
	nvs := []tuple{}

	mb.registry.Each(func(name string, i interface{}) {
		switch metric := i.(type) {
		case metrics.Counter:
			nvs = append(nvs, tuple{name, metric.Count()})
		case metrics.Timer:
			timer := metric.Snapshot()
			nvs = append(nvs, []tuple{
				{fmt.Sprintf("%s.count", name), timer.Count()},
				{fmt.Sprintf("%s.min", name), timer.Min()},
				{fmt.Sprintf("%s.max", name), timer.Max()},
				{fmt.Sprintf("%s.mean", name), timer.Mean()},
				{fmt.Sprintf("%s.std-dev", name), timer.StdDev()},
				{fmt.Sprintf("%s.one-minute", name), timer.Rate1()},
				{fmt.Sprintf("%s.five-minute", name), timer.Rate5()},
				{fmt.Sprintf("%s.fifteen-minute", name), timer.Rate15()},
				{fmt.Sprintf("%s.mean-rate", name), timer.RateMean()},
				{fmt.Sprintf("%s.50-percentile", name), timer.Percentile(0.5)},
				{fmt.Sprintf("%s.75-percentile", name), timer.Percentile(0.75)},
				{fmt.Sprintf("%s.95-percentile", name), timer.Percentile(0.95)},
				{fmt.Sprintf("%s.99-percentile", name), timer.Percentile(0.99)},
				{fmt.Sprintf("%s.999-percentile", name), timer.Percentile(0.999)},
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
