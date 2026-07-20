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

package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ghostunnel/ghostunnel/metrics"
	sem "golang.org/x/sync/semaphore"
)

// defaultRegistry/defaultMetrics provide the live handles New falls back to
// when a caller passes nil. This preserves the historical behavior of recording
// to a package-owned registry (formerly go-metrics' DefaultRegistry); callers
// that want to skip collection pass metrics.NilMetrics() explicitly. Nothing
// scrapes this registry, so it exists purely to keep New(nil) recording.
var (
	defaultRegistry = metrics.NewRegistry("ghostunnel")
	defaultMetrics  = metrics.LiveMetrics(defaultRegistry)
)

const (
	// LogConnections will log messages about open/closed connections.
	LogConnections = 1
	// LogConnectionErrors will log errors encountered during backend dialing, other errors (after handshake).
	LogConnectionErrors = 2
	// LogHandshakeErrors will log errors with new connections before/during handshake.
	LogHandshakeErrors = 4
	// LogEverything will log all things.
	LogEverything = LogHandshakeErrors | LogConnectionErrors | LogConnections
)

// Logger is used by this package to log messages
type Logger interface {
	Printf(format string, v ...any)
}

// DialFunc represents a function that can dial a backend/destination for forwarding connections.
type DialFunc func(context.Context) (net.Conn, error)

// Timeouts is the timeout policy applied to proxied connections. Every field
// may be zero: for Connect, Idle and MaxLifetime zero disables that timeout,
// while a zero Close closes the surviving direction of a half-closed
// connection immediately.
type Timeouts struct {
	// Connect limits the time to establish a connection/handshake.
	Connect time.Duration
	// Close is the idle (inactivity) timeout applied to the surviving
	// direction once a connection is half-closed: the surviving direction is
	// reaped only after Close passes with no data transferred. Zero means
	// immediate closure.
	Close time.Duration
	// Idle reaps a connection when no data moves in either direction for this
	// long while both directions are still open (pre-teardown). Activity in
	// either direction resets the clock for both. Zero disables it, in which
	// case an open connection is bounded only by Close after a half-close and
	// by MaxLifetime, if set.
	Idle time.Duration
	// MaxLifetime is the max lifetime for any connection, regardless of
	// circumstances. Zero disables it.
	MaxLifetime time.Duration
}

// Proxy will take incoming connections from a listener and forward them to
// a backend through the given dialer.
type Proxy struct {
	// Listener to accept connections on.
	Listener net.Listener
	// Timeouts is the timeout policy for proxied connections.
	Timeouts Timeouts
	// Dial function to reach backend to forward connections to.
	Dial DialFunc
	// Logger is used to log information messages about connections, errors.
	Logger Logger

	// Logging flags
	loggerFlags int
	// Enable HAproxy's PROXY protocol
	// see: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	proxyProtocol ProxyProtocolMode
	// Internal wait group to keep track of outstanding handlers.
	handlers *sync.WaitGroup
	// Semaphore to limit the max. number of connections.
	connSemaphore semaphore
	// Context & associated cancel func
	context context.Context
	cancel  context.CancelFunc
	// Guards Shutdown so the cancel/Close/Done sequence runs exactly once,
	// even under concurrent callers. handlers.Done() is not idempotent, so a
	// bare context.Err() check-then-act would let two goroutines both call
	// Done() and drive the WaitGroup counter negative (panic).
	shutdownOnce sync.Once
	// Pool for buffers
	pool sync.Pool
	// Metrics handles for the connection hot path. Either live (recording to a
	// registry) or no-op (NilMetrics) when no metrics sink is configured.
	metrics *metrics.Metrics
}

// New creates a new proxy.
func New(
	listener net.Listener,
	timeouts Timeouts,
	maxConcurrentConnections int64,
	dial DialFunc,
	logger Logger,
	loggerFlags int,
	proxyProtocol ProxyProtocolMode,
	connMetrics *metrics.Metrics) *Proxy {

	// A nil handle means "use the default registry" (the historical behavior);
	// callers that want to skip collection pass NilMetrics explicitly.
	if connMetrics == nil {
		connMetrics = defaultMetrics
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		Listener:      listener,
		Timeouts:      timeouts,
		Dial:          dial,
		Logger:        logger,
		loggerFlags:   loggerFlags,
		proxyProtocol: proxyProtocol,
		handlers:      &sync.WaitGroup{},
		context:       ctx,
		cancel:        cancel,
		metrics:       connMetrics,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, 1<<15 /* 32 KiB */)
				return &b
			},
		},
	}

	if maxConcurrentConnections > 0 {
		p.connSemaphore = sem.NewWeighted(maxConcurrentConnections)
	} else {
		p.connSemaphore = &unlimitedSemaphore{}
	}

	// Add one handler to the wait group, so that Wait() will always block until
	// Shutdown() is called even if the proxy hasn't started yet. This prevents
	// a race condition if someone calls Accept() in a Goroutine and then immediately
	// calls Wait() on the proxy object.
	p.handlers.Add(1)
	return p
}

// Shutdown tells the proxy to close the listener & stop accepting connections.
// Safe to call concurrently and repeatedly; the shutdown work runs exactly once.
func (p *Proxy) Shutdown() {
	p.shutdownOnce.Do(func() {
		p.cancel()
		p.Listener.Close()
		p.handlers.Done()
	})
}

// Wait until the proxy is shut down (listener closed, connections drained).
// This function will block even if the proxy isn't in the accept loop yet,
// so it's safe to concurrently run Accept() in a Goroutine and then immediately
// call Wait().
func (p *Proxy) Wait() {
	p.handlers.Wait()
}

// Backoff bounds for Accept errors. Bounds mirror net/http.Server.Serve.
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = 1 * time.Second
)

// Accept incoming connections and spawn Go routines to handle them and forward
// the data to the backend. Will stop accepting connections if Shutdown() is called.
// Run this in a Goroutine, call Wait() to block on proxy shutdown/connection drain.
func (p *Proxy) Accept() {
	// acceptBackoff is the current sleep delay after an Accept error. It
	// starts at zero, jumps to acceptBackoffMin on first error, doubles up
	// to acceptBackoffMax, and resets to zero after a successful Accept. This
	// prevents a hot loop on persistent errors like fd exhaustion (EMFILE).
	var acceptBackoff time.Duration

	for {
		// Acquire semaphore, to limit max concurrent connections
		err := p.connSemaphore.Acquire(p.context, 1)
		if err != nil {
			// Context was cancelled, we're done here
			return
		}

		// Reserve the handler slot BEFORE the blocking Accept(). This guarantees
		// that any connection Accept() hands back is already accounted for in the
		// WaitGroup, so Shutdown()'s Done() (which balances New()'s guard Add)
		// can never transiently drive the counter to zero while an accepted-but-
		// not-yet-registered connection is outstanding.
		p.handlers.Add(1)

		// Wait for new connection
		conn, err := p.Listener.Accept()
		if err != nil {
			// No connection to handle: release the reserved slot.
			p.handlers.Done()

			// Check if we're supposed to stop
			if err := p.context.Err(); err != nil {
				return
			}

			p.metrics.ErrorCounter.Inc(1)
			p.connSemaphore.Release(1)
			p.logConditional(LogConnectionErrors, "error accepting connection: %s", err)

			// Back off before retrying so we don't spin at 100% CPU on
			// persistent accept errors (e.g. fd exhaustion).
			if acceptBackoff == 0 {
				acceptBackoff = acceptBackoffMin
			} else {
				acceptBackoff = min(acceptBackoff*2, acceptBackoffMax)
			}
			select {
			case <-time.After(acceptBackoff):
			case <-p.context.Done():
				return
			}
			continue
		}
		// Successful accept: reset backoff.
		acceptBackoff = 0

		// Handler slot reserved above; the handler's cleanup defer calls Done().
		go func() {
			// Record the connection lifetime explicitly rather than via
			// Timer.Time: a no-op timer's Time() would not run the closure at
			// all, which would skip connection handling when metrics are off.
			// UpdateSince is deferred first so it fires last (after the close
			// defer below), matching Timer.Time's "measure the whole handler".
			startTime := time.Now()
			defer p.metrics.ConnTimer.UpdateSince(startTime)

			p.metrics.OpenCounter.Inc(1)
			p.metrics.TotalCounter.Inc(1)

			defer func() {
				conn.Close()
				p.metrics.OpenCounter.Dec(1)
				p.handlers.Done()
				p.connSemaphore.Release(1)
			}()

			ctx, cancel := context.WithTimeout(p.context, p.Timeouts.Connect)
			defer cancel()

			err := forceHandshake(ctx, conn, p.metrics)
			if err != nil {
				p.metrics.ErrorCounter.Inc(1)
				p.logConditional(LogHandshakeErrors, "error on TLS handshake from %s: %s", conn.RemoteAddr(), err)
				return
			}

			// TLS-ALPN-01 challenge probes complete the handshake to deliver
			// the challenge certificate, but carry no application data and
			// must never reach the backend. The handshake itself ran with
			// ClientAuth relaxed (see certloader/acmetlsconfig.go); refusing
			// to proxy ensures that relaxation cannot become an mTLS bypass.
			if isACMEChallengeConn(conn) {
				p.logConditional(LogConnections, "completed ACME TLS-ALPN-01 challenge from %s; not forwarding to backend", conn.RemoteAddr())
				return
			}

			backend, err := p.Dial(ctx)
			if err != nil {
				p.metrics.ErrorCounter.Inc(1)
				p.logConditional(LogConnectionErrors, "error on dial: %s", err)
				return
			}

			if p.proxyProtocol != ProxyProtocolOff {
				var tlsState *tls.ConnectionState
				if tlsConn, ok := conn.(*tls.Conn); ok {
					state := tlsConn.ConnectionState()
					tlsState = &state
				}
				h, err := proxyProtoHeader(conn, tlsState, p.proxyProtocol)
				if err != nil {
					p.metrics.ErrorCounter.Inc(1)
					p.logConditional(LogConnectionErrors, "error building proxy header: %s", err)
					backend.Close()
					return
				}
				if _, err = h.WriteTo(backend); err != nil {
					p.metrics.ErrorCounter.Inc(1)
					p.logConditional(LogConnectionErrors, "error writing proxy header: %s", err)
					backend.Close()
					return
				}
			}

			p.metrics.SuccessCounter.Inc(1)
			p.fuse(conn, backend)
		}()
	}
}

// isACMEChallengeConn reports whether the (already-handshaken) connection
// negotiated the TLS-ALPN-01 challenge protocol from RFC 8737. Such a
// connection is an ACME validator probe and must not be proxied to the
// backend: the relaxed ClientAuth in certloader/acmetlsconfig.go is scoped
// to making the handshake complete, not to authorizing application data.
func isACMEChallengeConn(conn net.Conn) bool {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return false
	}
	return tlsConn.ConnectionState().NegotiatedProtocol == "acme-tls/1"
}

// Force handshake. Handshake usually happens on first read/write, but we want
// to force it to make sure we can control the timeout for it. Otherwise,
// unauthenticated clients would be able to open connections and leave them
// hanging forever. Going through the handshake verifies that clients have a
// valid client cert and are allowed to talk to us.
func forceHandshake(ctx context.Context, conn net.Conn, m *metrics.Metrics) error {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		startTime := time.Now()
		defer m.HandshakeTimer.UpdateSince(startTime)

		err := tlsConn.HandshakeContext(ctx)
		if isTimeoutError(err) {
			// If we timed out, increment timeout metric
			m.HandshakeTimeoutCounter.Inc(1)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// Fuse connections together
func (p *Proxy) fuse(client, backend net.Conn) {
	// Copy from client -> backend, and from backend -> client
	start := time.Now()
	p.logConnectionMessage("opening", client, backend, -1, -1, time.Time{})

	// The watchdog is the sole owner of timeout enforcement for this pair (see
	// pairWatchdog).
	w := p.newPairWatchdog(client, backend)

	// For TCP and UNIX sockets, copyData calls closeRead and closeWrite for the
	// src/dst respectively. For TCP sockets, this will call the shutdown syscall
	// to block read/writes (and send a FIN packet). However, we still need to
	// free up the FDs after we're done by calling close.
	defer func() {
		_ = client.Close()
		_ = backend.Close()
	}()

	// Copy data to/from both ends of the connection.
	returnedC := make(chan int64, 1)
	forwardedC := make(chan int64, 1)
	go func() { returnedC <- p.copyData(client, backend, w) }()
	go func() { forwardedC <- p.copyData(backend, client, w) }()

	// Run the watchdog inline, then wait on results. runWatchdog returns after
	// it reaps or once the second directionFinished signals completion, so the
	// waits below never block on a live watchdog.
	p.runWatchdog(w)
	returned := <-returnedC
	forwarded := <-forwardedC

	p.logConnectionMessage("closed", client, backend, forwarded, returned, start)
}

// trackedConn wraps the connections passed to io.CopyBuffer. It serves two
// purposes:
//
//  1. Hide the WriteTo/ReadFrom methods on TCPConn and UnixConn. CopyBuffer
//     prefers WriteTo/ReadFrom when available, to use splice/sendfile for
//     better perf. However, that fails if one side is a tls.Conn, because TLS
//     connections must go through user space for cryptographic operations. If
//     splice/sendfile aren't usable, the stdlib falls back to io.Copy, which
//     allocates its own buffer and throws away the pooled buf we pass in. To
//     keep our pooled buffer we define only Read/Write here and never embed
//     net.Conn, so WriteTo/ReadFrom stay hidden. Note this is hard to catch in
//     testing: net.Pipe() doesn't implement WriteTo/ReadFrom, so tests over
//     pipes won't exercise this path.
//
//     See: https://github.com/golang/go/issues/16474
//     See: https://github.com/golang/go/issues/67074
//
//  2. Report activity to the watchdog. After each successful read or write
//     (n>0) the shim calls watchdog.recordActivity(), which resets the
//     connection-wide idle clock. The watchdog, not a socket deadline, bounds
//     an idle or half-closed pair; this shim's only job is to signal that
//     data moved.
type trackedConn struct {
	conn     net.Conn
	watchdog *pairWatchdog
}

func (tc *trackedConn) Read(p []byte) (int, error) {
	n, err := tc.conn.Read(p)
	if n > 0 {
		tc.watchdog.recordActivity()
	}
	return n, err
}

// Write records activity too: a write can block while a slow peer drains it,
// long after the read that fed it reset the clock, and a slow-but-progressing
// transfer must not be reaped as stale. Progress inside a single blocked
// Write is not observable through net.Conn, so a write that drains slower
// than the timeout window can still be reaped, but each completed write
// proves data moved and resets the idle clock.
func (tc *trackedConn) Write(p []byte) (int, error) {
	n, err := tc.conn.Write(p)
	if n > 0 {
		tc.watchdog.recordActivity()
	}
	return n, err
}

// Copy data between two connections
func (p *Proxy) copyData(dst net.Conn, src net.Conn, w *pairWatchdog) (written int64) {
	// When we're done copying the data, we close the read/write sides of the
	// src/dst respectively. This uses the shutdown system call to send a FIN
	// packet to the other end of the connection. By only closing the read/write
	// sides specifically, we retain the ability to forward or return data in a
	// case where a client has only half-closed the connection.
	//
	// directionFinished then reports this direction's end to the watchdog: the
	// first call switches it to the CloseTimeout regime, granting the surviving
	// direction a fresh window. The watchdog (not a socket deadline) bounds that
	// direction from here on: it is reaped after CloseTimeout of silence
	// (clamped to MaxConnLifetime), but an active transfer is never cut off.
	// Without this bound a misbehaving peer could keep the connection open
	// forever, tying up the other copyData Go routine. The second call tells
	// the watchdog the pair is done, so it stops guarding and lets fuse return.
	defer func() {
		closeRead(src)
		closeWrite(dst)
		w.directionFinished()
	}()

	// Get a buffer for copy from the pool of shared buffers, to reduce allocs.
	buf := p.pool.Get().(*[]byte)
	defer p.pool.Put(buf)

	// The trackedConn shims hide WriteTo/ReadFrom (to keep our pooled buffer)
	// and report activity to the watchdog (see trackedConn).
	written, err := io.CopyBuffer(
		&trackedConn{conn: dst, watchdog: w},
		&trackedConn{conn: src, watchdog: w},
		*buf)

	// A watchdog reap surfaces here as a closed-connection error (silent). Only
	// genuine peer I/O errors are counted and logged; the watchdog owns timeout
	// counting/logging, so copyData no longer classifies timeouts itself.
	if err != nil && !isClosedConnectionError(err) {
		p.metrics.ConnErrorCounter.Inc(1)
		p.logConditional(LogConnectionErrors, "error during copy: %s", err)
	}

	return written
}

// Log information message about connection
func (p *Proxy) logConnectionMessage(action string, dst net.Conn, src net.Conn, forwarded, returned int64, start time.Time) {
	if (p.loggerFlags & LogConnections) == 0 {
		return
	}
	p.Logger.Printf(
		"%s pipe: %s:%s [%s] <-> %s:%s [%s] %s",
		action,
		dst.RemoteAddr().Network(),
		dst.RemoteAddr().String(),
		peerCertificatesString(dst),
		src.RemoteAddr().Network(),
		src.RemoteAddr().String(),
		peerCertificatesString(src),
		connStatsString(forwarded, returned, time.Since(start)),
	)
}

func (p *Proxy) logConditional(flag int, msg string, args ...any) {
	if (p.loggerFlags & flag) > 0 {
		p.Logger.Printf(msg, args...)
	}
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, context.DeadlineExceeded)
}

func isClosedConnectionError(err error) bool {
	// A nil error is not a closed-connection error. Guard here so callers can
	// classify a copy result unconditionally (err.Error() below would panic on
	// nil).
	if err == nil {
		return false
	}

	// A watchdog reap closes the conn concurrently with an in-flight Read/Write,
	// which surfaces as net.ErrClosed (possibly wrapped). Match it structurally
	// so classification of a reap doesn't depend on error strings. String
	// matching was never exercised on this concurrent-close path for tls.Conn.
	if errors.Is(err, net.ErrClosed) {
		return true
	}

	// Abrupt peer termination (RST / broken pipe) is routine for a proxy —
	// impatient clients, health checks, and idle keep-alive resets all cause
	// it — and is not actionable, so treat it the same as an orderly close.
	// errors.Is unwraps net.OpError, so these match whether or not the error
	// is wrapped in one. Both errnos are defined on Unix and Windows.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}

	// Pipe conns (net.Pipe, used in tests) don't return net.ErrClosed and are
	// only recognizable by their error string.
	return strings.Contains(err.Error(), "closed pipe")
}

func closeRead(conn net.Conn) {
	switch c := conn.(type) {
	case *net.TCPConn:
		_ = c.CloseRead()
	case *net.UnixConn:
		_ = c.CloseRead()
	case *tls.Conn:
		// tls.Conn has no CloseRead(): we can't shut down only the read
		// side without tearing down the whole connection. Do nothing here
		// and let the watchdog reap the pair after CloseTimeout of silence
		// (the surviving direction's activity keeps the pair alive until then).
		// Closing it here would kill the opposite (still-live) write direction,
		// dropping in-flight return traffic.
	default:
		_ = c.Close()
	}
}

func closeWrite(conn net.Conn) {
	switch c := conn.(type) {
	case *net.TCPConn:
		_ = c.CloseWrite()
	case *net.UnixConn:
		_ = c.CloseWrite()
	case *tls.Conn:
		// CloseWrite sends a TLS close_notify alert to the peer (a clean
		// half-close of the write side) without closing the underlying
		// socket, so the opposite direction can keep reading/forwarding.
		_ = c.CloseWrite()
	default:
		_ = c.Close()
	}
}
