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
	"net"
	"strconv"
	"time"
)

// writeGraphite writes the metrics snapshot in Graphite's line protocol
// ("<path> <value> <timestamp>\n") to w. It reproduces the kept subset of
// cyberdelia/go-metrics-graphite's output: counters emit ".count"; gauges emit
// ".value"; timers emit count/min/max/mean/{50,75,95,99}-percentile. The
// dropped fields (count_ps, std-dev, the rate fields, and .999-percentile) are
// intentionally absent — see docs/networking/metrics.md.
//
// Durations are reported in nanoseconds (DurationUnit was time.Nanosecond).
// Every value is rendered with gval in its shortest exact decimal form;
// line order is not significant.
//
// The returned error is the first write error, if any: bufio.Writer latches
// the first failure and returns it from Flush, so a partial write can never
// be reported as success.
func (r *Registry) writeGraphite(w io.Writer, now int64) error {
	s := r.snapshot()
	bw := bufio.NewWriter(w)

	line := func(dotted, suffix string, value float64) {
		fmt.Fprintf(bw, "%s.%s.%s %s %d\n", r.prefix, dotted, suffix, gval(value), now)
	}

	for _, sg := range s.singles {
		switch sg.kind {
		case kindGauge:
			line(sg.dotted, "value", sg.value)
		default: // kindCounter (counters and the gauge-like conn.open)
			line(sg.dotted, "count", sg.value)
		}
	}
	for _, t := range s.timers {
		line(t.dotted, "count", float64(t.count))
		line(t.dotted, "min", float64(t.min))
		line(t.dotted, "max", float64(t.max))
		line(t.dotted, "mean", t.mean)
		line(t.dotted, "50-percentile", t.p50)
		line(t.dotted, "75-percentile", t.p75)
		line(t.dotted, "95-percentile", t.p95)
		line(t.dotted, "99-percentile", t.p99)
	}
	return bw.Flush()
}

// gval renders a metric value in its shortest exact decimal form (e.g. 3, 20,
// 0.0023), so integer-valued metrics print without a trailing ".0".
func gval(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// StartGraphitePush starts a background goroutine that connects to a Graphite
// server at addr and flushes the metrics snapshot every interval over raw TCP,
// replacing cyberdelia/go-metrics-graphite. It backs --metrics-graphite.
//
// The goroutine runs for the remaining lifetime of the process by design:
// Ghostunnel starts at most one push loop at startup and never tears it down
// before exit, so there is deliberately no stop mechanism.
func (r *Registry) StartGraphitePush(addr *net.TCPAddr, interval time.Duration, logger Logger) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if err := r.graphiteFlush(addr); err != nil {
				logger.Printf("error reporting metrics to graphite: %s", err)
			}
		}
	}()
}

// graphiteTimeout bounds a single flush (dial + write). A firewalled or dead
// endpoint would otherwise block the push goroutine for the OS-level SYN or
// TCP-retransmit timeout (potentially minutes), silently dropping metrics.
const graphiteTimeout = 10 * time.Second

func (r *Registry) graphiteFlush(addr *net.TCPAddr) error {
	conn, err := net.DialTimeout("tcp", addr.String(), graphiteTimeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	return r.writeGraphiteConn(conn, graphiteTimeout, time.Now().Unix())
}

// writeGraphiteConn sets a deadline bounding the whole write, then renders the
// snapshot to conn. Split out from graphiteFlush so the deadline behavior can
// be exercised against an unread connection without a live Graphite server.
func (r *Registry) writeGraphiteConn(conn net.Conn, timeout time.Duration, now int64) error {
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	return r.writeGraphite(conn, now)
}
