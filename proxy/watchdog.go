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

package proxy

import (
	"net"
	"sync/atomic"
	"time"
)

// pairWatchdog reaps a fused connection pair when no data moves for the
// current window, or when the pair outlives MaxConnLifetime. It is the only
// code that decides "this pair timed out": it closes both conns (unblocking
// any in-flight Read/Write), logs, and counts the metric. Because a third
// party does the reaping, the two copyData directions never coordinate
// teardown between themselves and never need to reconstruct *why* a copy
// ended from error types. A reap surfaces to them as an ordinary
// closed-connection error.
//
// The pair moves through three phases. The copyData defers signal each
// transition via directionFinished.
//
//   - Open: both directions copying. The idle window is IdleTimeout
//     (0 = none). Activity anywhere on the pair resets the clock. Idle is
//     deliberately a property of the connection, not a direction, so an
//     active but asymmetric transfer (e.g. a long download the client is
//     silently receiving) is never reaped mid-stream.
//   - Half-closed: the first direction has returned (one value sent on
//     halfClosedC). The surviving direction is reaped after CloseTimeout of
//     silence.
//   - Finished: the second direction has returned (doneC closed). The
//     watchdog, which runs inline on the fuse goroutine, exits.
//
// MaxConnLifetime, when set, caps every deadline in every phase.
type pairWatchdog struct {
	lastActivity     atomic.Int64  // UnixNano of last successful transfer either direction
	finished         atomic.Int32  // count of copyData directions that have returned (0..2)
	idleTimeout      time.Duration // 0 = no idle timeout while fully open
	closeTimeout     time.Duration
	lifetimeDeadline time.Time // start + MaxConnLifetime; zero if unset
	client           net.Conn
	backend          net.Conn
	halfClosedC      chan struct{} // buffered(1); receives one value when the pair half-closes
	doneC            chan struct{} // closed when the pair finishes
}

// newPairWatchdog builds the watchdog for one fused pair.
func (p *Proxy) newPairWatchdog(client, backend net.Conn) *pairWatchdog {
	w := &pairWatchdog{
		idleTimeout:  p.Timeouts.Idle,
		closeTimeout: p.Timeouts.Close,
		client:       client,
		backend:      backend,
		halfClosedC:  make(chan struct{}, 1),
		doneC:        make(chan struct{}),
	}
	if p.Timeouts.MaxLifetime > 0 {
		w.lifetimeDeadline = time.Now().Add(p.Timeouts.MaxLifetime)
	}

	// The activity bump is important here, as a zero lastActivity would read as
	// a 1970 deadline and reap the pair instantly the first time a window is
	// armed.
	w.recordActivity()
	return w
}

// recordActivity marks the pair as active now: it is called after every
// successful read or write in either direction, so the watchdog's idle clock
// is reset by data movement anywhere on the pair.
func (w *pairWatchdog) recordActivity() {
	w.lastActivity.Store(time.Now().UnixNano())
}

// lastActivityTime returns the time of the last transfer in either direction.
func (w *pairWatchdog) lastActivityTime() time.Time {
	return time.Unix(0, w.lastActivity.Load())
}

// halfClosed reports whether the pair has left the open phase: at least one
// direction has finished (or the pair is done entirely).
func (w *pairWatchdog) halfClosed() bool {
	return w.finished.Load() >= 1
}

// directionFinished is called by each copyData defer as its direction returns.
// The first call moves the pair to the half-closed phase; the second marks it
// finished so the inline watchdog exits promptly. Without that second signal,
// every cleanly-closed connection would hold fuse and the accept handler's
// semaphore slot for a full CloseTimeout.
//
// The atomic Add serializes the two calls even when both directions finish at
// the same instant, which is routine (near-simultaneous FINs). Exactly one
// caller sees each count, so the buffered send never blocks and the close
// happens exactly once.
//
// recordActivity() MUST come first. If lastActivity were stale, the survivor
// would be reaped instantly instead of after CloseTimeout. A stale value is
// possible when IdleTimeout == 0, where a pair may sit silent indefinitely
// before the half-close.
func (w *pairWatchdog) directionFinished() {
	w.recordActivity()
	switch w.finished.Add(1) {
	case 1:
		w.halfClosedC <- struct{}{}
	case 2:
		close(w.doneC)
	}
}

// reapCause identifies which timeout policy a reap deadline belongs to. It is
// determined by reapDeadline when the deadline is computed, so reapPair never
// has to re-derive the cause from watchdog state after the fact.
type reapCause int

const (
	// reapNone means no policy currently applies (fully open, IdleTimeout == 0,
	// no MaxConnLifetime): there is no reap deadline.
	reapNone reapCause = iota
	// reapIdle is IdleTimeout of silence while both directions are open.
	reapIdle
	// reapHalfClosed is CloseTimeout of silence after a half-close: the
	// surviving peer neither transferred data nor closed within the window.
	reapHalfClosed
	// reapLifetime is the MaxConnLifetime hard cap.
	reapLifetime
)

// reapDeadline returns when the pair should be reaped absent further activity,
// and the policy that deadline belongs to (reapNone => no deadline). Two
// candidate deadlines compete and the earlier one wins. The first is the
// activity-based deadline: CloseTimeout of silence once half-closed (zero =>
// immediate), or IdleTimeout of silence while fully open (zero => none). The
// second is the fixed lifetime cap, if set. The cause follows the winner and
// selects the reap's log message.
func (w *pairWatchdog) reapDeadline() (time.Time, reapCause) {
	var at time.Time
	cause := reapNone
	switch {
	case w.halfClosed():
		at = w.lastActivityTime().Add(w.closeTimeout)
		cause = reapHalfClosed
	case w.idleTimeout > 0:
		at = w.lastActivityTime().Add(w.idleTimeout)
		cause = reapIdle
	}
	if !w.lifetimeDeadline.IsZero() && (cause == reapNone || w.lifetimeDeadline.Before(at)) {
		at = w.lifetimeDeadline
		cause = reapLifetime
	}
	return at, cause
}

// runWatchdog is the watchdog loop for one pair: reap the pair when it is
// stale, otherwise sleep until the deadline or a phase change and recheck.
// Waking with nothing to do is harmless, so the sleep only needs to be an
// upper bound: the armed deadline passing does not by itself mean the pair is
// stale, since activity may have pushed the deadline forward after the timer
// was armed. It exits when the pair finishes or after it reaps.
func (p *Proxy) runWatchdog(w *pairWatchdog) {
	// One timer reused across iterations: time.After would allocate a fresh
	// runtime timer on every wakeup. It starts stopped and is only ever armed
	// via Reset (safe without draining under the Go 1.23+ timer semantics
	// this module requires). A deadline, once present, never goes away,
	// half-close never reverts and the timeouts are fixed. Thus iterations
	// without one can only occur while the timer has never been armed, and a
	// stopped timer's channel never delivers: the select then blocks until a
	// phase change.
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		reapAt, cause := w.reapDeadline()
		if cause != reapNone && !time.Now().Before(reapAt) {
			p.reapPair(w, cause)
			return
		}
		if cause != reapNone {
			timer.Reset(time.Until(reapAt))
		}
		select {
		case <-timer.C: // Wait until we need to re-check deadline
		case <-w.halfClosedC: // State change: deadline shrunk to CloseTimeout
		case <-w.doneC: // Both connections are done; exit
			return
		}
	}
}

// reapPair closes both conns, unblocking any blocked copy direction; the reap
// surfaces there as an ordinary closed-connection error. Every reap counts
// under conn.timeout; the cause picks the log message.
func (p *Proxy) reapPair(w *pairWatchdog, cause reapCause) {
	_ = w.client.Close()
	_ = w.backend.Close()
	p.metrics.ConnTimeoutCounter.Inc(1)
	switch cause {
	case reapIdle:
		p.logConditional(LogConnections, "connection closed by timeout: no activity for %s", w.idleTimeout)
	case reapHalfClosed:
		p.logConditional(LogConnections, "connection closed by timeout: no activity for %s after half-close", w.closeTimeout)
	case reapLifetime:
		p.logConditional(LogConnections, "connection closed by timeout: max connection lifetime reached")
	}
}
