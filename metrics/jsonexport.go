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
	"io"
	"net/http"
	"time"
)

// Logger is the minimal logging surface the push reporters use. It must be
// non-nil; the push loops log directly through it.
type Logger interface {
	Printf(format string, v ...any)
}

// serializeJSON reproduces go-sq-metrics' SerializeMetrics output: one
// {timestamp, metric, value, hostname} object per emitted value. Counters and
// gauges emit a single value; timers expand to
// count/min/max/mean/{50,75,95,99}-percentile. The "metric" field is the
// prefix-prepended dotted name. Single values carry the float64 Prometheus
// gathers; Go marshals integer-valued float64 without a decimal point, so
// counters encode as plain integers. Order is not significant.
func (r *Registry) serializeJSON() []map[string]any {
	s := r.snapshot()
	now := time.Now().Unix()

	out := []map[string]any{}
	emit := func(dotted string, value any) {
		out = append(out, map[string]any{
			"timestamp": now,
			"metric":    r.prefix + "." + dotted,
			"value":     value,
			"hostname":  r.hostname,
		})
	}

	for _, sg := range s.singles {
		emit(sg.dotted, sg.value)
	}
	for _, t := range s.timers {
		emit(t.dotted+".count", t.count)
		emit(t.dotted+".min", t.min)
		emit(t.dotted+".max", t.max)
		emit(t.dotted+".mean", t.mean)
		emit(t.dotted+".50-percentile", t.p50)
		emit(t.dotted+".75-percentile", t.p75)
		emit(t.dotted+".95-percentile", t.p95)
		emit(t.dotted+".99-percentile", t.p99)
	}
	return out
}

// jsonBytes marshals the current metrics snapshot to its JSON representation.
func (r *Registry) jsonBytes() ([]byte, error) {
	return json.Marshal(r.serializeJSON())
}

// ServeHTTP serves the JSON metrics representation. It backs /_metrics/json and
// the bare /_metrics endpoint.
func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	raw, err := r.jsonBytes()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// StartPostLoop starts a background goroutine that POSTs the JSON metrics
// representation to url every interval, replacing go-sq-metrics' publishMetrics.
// It backs --metrics-url.
func (r *Registry) StartPostLoop(url string, client *http.Client, interval time.Duration, logger Logger) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := r.postOnce(url, client); err != nil && err != io.EOF {
				logger.Printf("error reporting metrics: %s", err)
			}
		}
	}()
}

func (r *Registry) postOnce(url string, client *http.Client) error {
	raw, err := r.jsonBytes()
	if err != nil {
		return err
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(raw))
	if resp != nil {
		defer resp.Body.Close()
	}
	return err
}
