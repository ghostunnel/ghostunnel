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

func (mb metricsConfig) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (mb *metricsConfig) serializeMetric(now int64, name string, value interface{}) map[string]interface{} {
	return map[string]interface{}{
		"timestamp": now,
		"metric":    fmt.Sprintf("%s.%s", mb.prefix, name),
		"value":     value,
		"hostname":  mb.hostname,
	}
}

func (mb *metricsConfig) serializeMetrics() []map[string]interface{} {
	names := []string{}
	values := []interface{}{}
	du := float64(1 * time.Nanosecond)

	mb.registry.Each(func(name string, i interface{}) {
		switch metric := i.(type) {
		case metrics.Counter:
			names = append(names, name)
			values = append(values, metric.Count())
		case metrics.Timer:
			timer := metric.Snapshot()
			names = append(names, []string{
				fmt.Sprintf("%s.count", name),
				fmt.Sprintf("%s.min", name),
				fmt.Sprintf("%s.max", name),
				fmt.Sprintf("%s.mean", name),
				fmt.Sprintf("%s.std-dev", name),
				fmt.Sprintf("%s.one-minute", name),
				fmt.Sprintf("%s.five-minute", name),
				fmt.Sprintf("%s.fifteen-minute", name),
				fmt.Sprintf("%s.mean-rate", name),
				fmt.Sprintf("%s.50-percentile", name),
				fmt.Sprintf("%s.75-percentile", name),
				fmt.Sprintf("%s.95-percentile", name),
				fmt.Sprintf("%s.99-percentile", name),
				fmt.Sprintf("%s.999-percentile", name),
			}...)
			values = append(values, []interface{}{
				timer.Count(),
				timer.Min() / int64(du),
				timer.Max() / int64(du),
				timer.Mean() / du,
				timer.StdDev() / du,
				timer.Rate1(),
				timer.Rate5(),
				timer.Rate15(),
				timer.RateMean(),
				timer.Percentile(0.5) / du,
				timer.Percentile(0.75) / du,
				timer.Percentile(0.95) / du,
				timer.Percentile(0.99) / du,
				timer.Percentile(0.999) / du,
			}...)
		}
	})

	now := time.Now().Unix()
	out := []map[string]interface{}{}
	for i, name := range names {
		out = append(out, mb.serializeMetric(now, name, values[i]))
	}

	return out
}
