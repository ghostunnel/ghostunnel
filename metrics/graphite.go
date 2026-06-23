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
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// writeGraphite writes the metrics snapshot in Graphite's line protocol
// ("<path> <value> <timestamp>\n") to w. It reproduces the kept subset of
// cyberdelia/go-metrics-graphite's output: counters emit ".count"; gauges emit
// ".value"; timers emit count/min/max/mean/{50,75,95,99}-percentile. The
// dropped fields (count_ps, std-dev, the rate fields, and .999-percentile) are
// intentionally absent — see docs/networking/metrics.md.
//
// Durations are reported in nanoseconds (DurationUnit was time.Nanosecond), so
// min/max are integers and mean/percentiles use two decimal places, matching
// the historical formatting verbs.
func (r *Registry) writeGraphite(w io.Writer, now int64) {
	s := r.snapshot()
	bw := bufio.NewWriter(w)

	for _, sg := range s.singles {
		switch sg.kind {
		case kindGauge:
			if sg.isFloat {
				fmt.Fprintf(bw, "%s.%s.value %f %d\n", r.prefix, sg.dotted, sg.f, now)
			} else {
				fmt.Fprintf(bw, "%s.%s.value %d %d\n", r.prefix, sg.dotted, sg.i, now)
			}
		default: // kindCounter (counters and the gauge-like conn.open)
			fmt.Fprintf(bw, "%s.%s.count %d %d\n", r.prefix, sg.dotted, sg.i, now)
		}
	}
	for _, t := range s.timers {
		fmt.Fprintf(bw, "%s.%s.count %d %d\n", r.prefix, t.dotted, t.count, now)
		fmt.Fprintf(bw, "%s.%s.min %d %d\n", r.prefix, t.dotted, t.min, now)
		fmt.Fprintf(bw, "%s.%s.max %d %d\n", r.prefix, t.dotted, t.max, now)
		fmt.Fprintf(bw, "%s.%s.mean %.2f %d\n", r.prefix, t.dotted, t.mean, now)
		fmt.Fprintf(bw, "%s.%s.50-percentile %.2f %d\n", r.prefix, t.dotted, t.p50, now)
		fmt.Fprintf(bw, "%s.%s.75-percentile %.2f %d\n", r.prefix, t.dotted, t.p75, now)
		fmt.Fprintf(bw, "%s.%s.95-percentile %.2f %d\n", r.prefix, t.dotted, t.p95, now)
		fmt.Fprintf(bw, "%s.%s.99-percentile %.2f %d\n", r.prefix, t.dotted, t.p99, now)
	}
	_ = bw.Flush()
}

// StartGraphitePush starts a background goroutine that connects to a Graphite
// server at addr and flushes the metrics snapshot every interval over raw TCP,
// replacing cyberdelia/go-metrics-graphite. It backs --metrics-graphite.
func (r *Registry) StartGraphitePush(addr *net.TCPAddr, interval time.Duration, logger Logger) {
	logf := func(format string, v ...any) {
		if logger != nil {
			logger.Printf(format, v...)
		} else {
			log.Printf(format, v...)
		}
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := r.graphiteFlush(addr); err != nil {
				logf("error reporting metrics to graphite: %s", err)
			}
		}
	}()
}

func (r *Registry) graphiteFlush(addr *net.TCPAddr) error {
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	r.writeGraphite(conn, time.Now().Unix())
	return nil
}
