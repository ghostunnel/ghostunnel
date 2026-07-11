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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	metrics "github.com/rcrowley/go-metrics"
	sem "golang.org/x/sync/semaphore"
)

// ProxyProtocolMode controls PROXY protocol v2 header generation.
type ProxyProtocolMode int

const (
	// ProxyProtocolOff disables PROXY protocol headers.
	ProxyProtocolOff ProxyProtocolMode = iota
	// ProxyProtocolConn sends connection info (src/dst IP+port) only, no TLVs.
	ProxyProtocolConn
	// ProxyProtocolTLS sends connection info + TLS metadata (version, ALPN, SNI) without client cert details.
	ProxyProtocolTLS
	// ProxyProtocolTLSFull sends connection info + all TLVs including client certificate.
	ProxyProtocolTLSFull
)

var (
	openCounter             = metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	connTimeoutCounter      = metrics.GetOrRegisterCounter("conn.timeout", metrics.DefaultRegistry)
	totalCounter            = metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter          = metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter            = metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	handshakeTimeoutCounter = metrics.GetOrRegisterCounter("accept.timeout", metrics.DefaultRegistry)
	handshakeTimer          = metrics.GetOrRegisterTimer("conn.handshake", metrics.DefaultRegistry)
	connTimer               = metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)

	// defaultMetrics wraps the package-level handles registered above on the
	// default registry. New uses it when a caller passes nil, preserving the
	// historical behavior of reporting to metrics.DefaultRegistry.
	defaultMetrics = &Metrics{
		OpenCounter:             openCounter,
		ConnTimeoutCounter:      connTimeoutCounter,
		TotalCounter:            totalCounter,
		SuccessCounter:          successCounter,
		ErrorCounter:            errorCounter,
		HandshakeTimeoutCounter: handshakeTimeoutCounter,
		HandshakeTimer:          handshakeTimer,
		ConnTimer:               connTimer,
	}
)

// Metrics holds the go-metrics handles updated on the connection hot path.
// Injecting the handles (instead of reading package globals) lets the caller
// decide, once at startup, whether to collect at all: pass LiveMetrics to
// record against a registry, or NilMetrics to make every update a no-op when no
// metrics sink is configured. The metric names are part of Ghostunnel's
// exported surface and must not change.
type Metrics struct {
	OpenCounter             metrics.Counter // conn.open
	ConnTimeoutCounter      metrics.Counter // conn.timeout
	TotalCounter            metrics.Counter // accept.total
	SuccessCounter          metrics.Counter // accept.success
	ErrorCounter            metrics.Counter // accept.error
	HandshakeTimeoutCounter metrics.Counter // accept.timeout
	HandshakeTimer          metrics.Timer   // conn.handshake
	ConnTimer               metrics.Timer   // conn.lifetime
}

// LiveMetrics registers the connection metrics under their canonical names on
// the given registry and returns handles that record to it. Registration is
// idempotent (GetOrRegister), so repeated calls with the same registry return
// the same underlying handles.
func LiveMetrics(registry metrics.Registry) *Metrics {
	return &Metrics{
		OpenCounter:             metrics.GetOrRegisterCounter("conn.open", registry),
		ConnTimeoutCounter:      metrics.GetOrRegisterCounter("conn.timeout", registry),
		TotalCounter:            metrics.GetOrRegisterCounter("accept.total", registry),
		SuccessCounter:          metrics.GetOrRegisterCounter("accept.success", registry),
		ErrorCounter:            metrics.GetOrRegisterCounter("accept.error", registry),
		HandshakeTimeoutCounter: metrics.GetOrRegisterCounter("accept.timeout", registry),
		HandshakeTimer:          metrics.GetOrRegisterTimer("conn.handshake", registry),
		ConnTimer:               metrics.GetOrRegisterTimer("conn.lifetime", registry),
	}
}

// NilMetrics returns metrics handles whose updates are all no-ops. Use it when
// no metrics sink is configured so the connection hot path spends nothing
// updating contended timers; nothing observes the registry in that case anyway.
func NilMetrics() *Metrics {
	return &Metrics{
		OpenCounter:             metrics.NilCounter{},
		ConnTimeoutCounter:      metrics.NilCounter{},
		TotalCounter:            metrics.NilCounter{},
		SuccessCounter:          metrics.NilCounter{},
		ErrorCounter:            metrics.NilCounter{},
		HandshakeTimeoutCounter: metrics.NilCounter{},
		HandshakeTimer:          metrics.NilTimer{},
		ConnTimer:               metrics.NilTimer{},
	}
}

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

// Proxy will take incoming connections from a listener and forward them to
// a backend through the given dialer.
type Proxy struct {
	// Listener to accept connections on.
	Listener net.Listener
	// ConnectTimeout, CloseTimeout limit time to execute connects/close connections.
	ConnectTimeout, CloseTimeout time.Duration
	// MaxConnLifetime is the max lifetime for any connection, regardless of circumstances.
	MaxConnLifetime time.Duration
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
	// Pool for buffers
	pool sync.Pool
	// Metrics handles for the connection hot path. Either live (recording to a
	// registry) or no-op (NilMetrics) when no metrics sink is configured.
	metrics *Metrics
}

// PROXY protocol v2 client flag constants (from spec section 2.2.5).
const (
	pp2ClientSSL      = 0x01
	pp2ClientCertConn = 0x02
	pp2ClientCertSess = 0x04
)

func transportProtocol(c net.Conn) proxyproto.AddressFamilyAndProtocol {
	switch addr := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return proxyproto.TCPv4
		}
		return proxyproto.TCPv6
	case *net.UnixAddr:
		// Unix-domain listeners are valid PROXY protocol carriers; without
		// this case, go-proxyproto's formatVersion2 rejects the *net.UnixAddr
		// SourceAddr/DestinationAddr as ErrInvalidAddress and every connection
		// fails per-connection at WriteTo time.
		return proxyproto.UnixStream
	}
	return proxyproto.UNSPEC
}

func proxyProtoHeader(c net.Conn, tlsState *tls.ConnectionState, mode ProxyProtocolMode, logger Logger) *proxyproto.Header {
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: transportProtocol(c),
		SourceAddr:        c.RemoteAddr(),
		DestinationAddr:   c.LocalAddr(),
	}

	if tlsState != nil && mode >= ProxyProtocolTLS {
		tlvs, err := buildTLVs(tlsState, mode)
		if err != nil {
			logger.Printf("proxy: failed to build PROXY protocol TLVs: %s", err)
		} else if len(tlvs) > 0 {
			if err := h.SetTLVs(tlvs); err != nil {
				logger.Printf("proxy: failed to set PROXY protocol TLVs: %s", err)
			}
		}
	}

	return h
}

// buildTLVs constructs the top-level TLV list from TLS connection state.
func buildTLVs(state *tls.ConnectionState, mode ProxyProtocolMode) ([]proxyproto.TLV, error) {
	var tlvs []proxyproto.TLV

	// PP2_TYPE_ALPN
	if state.NegotiatedProtocol != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_ALPN,
			Value: []byte(state.NegotiatedProtocol),
		})
	}

	// PP2_TYPE_AUTHORITY (SNI)
	if state.ServerName != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_AUTHORITY,
			Value: []byte(state.ServerName),
		})
	}

	// PP2_TYPE_SSL with nested sub-TLVs
	sslTLV, err := buildSSLTLV(state, mode)
	if err != nil {
		return nil, err
	}
	tlvs = append(tlvs, sslTLV)

	return tlvs, nil
}

// buildSSLTLV constructs the PP2_TYPE_SSL TLV with its 5-byte sub-header
// and nested sub-TLVs containing TLS connection metadata.
func buildSSLTLV(state *tls.ConnectionState, mode ProxyProtocolMode) (proxyproto.TLV, error) {
	var subTLVs []proxyproto.TLV

	// Always include TLS version
	subTLVs = append(subTLVs, proxyproto.TLV{
		Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
		Value: []byte(tls.VersionName(state.Version)),
	})

	// Client certificate fields (only in TLSFull mode and if a cert was presented)
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if cert.Subject.CommonName != "" {
			subTLVs = append(subTLVs, proxyproto.TLV{
				Type:  proxyproto.PP2_SUBTYPE_SSL_CN,
				Value: []byte(cert.Subject.CommonName),
			})
		}

		// Full DER-encoded client certificate (extension, not in HAProxy spec)
		subTLVs = append(subTLVs, proxyproto.TLV{
			Type:  proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT,
			Value: cert.Raw,
		})
	}

	// Build 5-byte sub-header: 1 byte flags + 4 bytes verify result
	var flags byte = pp2ClientSSL
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		// Set both flags: Ghostunnel doesn't distinguish connection-level vs
		// session-level (resumed) cert presentation — the cert was verified
		// on this connection either way.
		flags |= pp2ClientCertConn | pp2ClientCertSess
	}
	var header [5]byte
	header[0] = flags
	binary.BigEndian.PutUint32(header[1:5], 0) // verify=0, cert already verified by ghostunnel

	// Encode sub-TLVs and append after the 5-byte header
	subTLVBytes, err := proxyproto.JoinTLVs(subTLVs)
	if err != nil {
		return proxyproto.TLV{}, fmt.Errorf("encoding SSL sub-TLVs: %w", err)
	}

	value := make([]byte, len(header)+len(subTLVBytes))
	copy(value, header[:])
	copy(value[len(header):], subTLVBytes)

	return proxyproto.TLV{Type: proxyproto.PP2_TYPE_SSL, Value: value}, nil
}

// New creates a new proxy.
func New(
	listener net.Listener,
	connectTimeout, closeTimeout, maxConnLifetime time.Duration,
	maxConcurrentConnections int64,
	dial DialFunc,
	logger Logger,
	loggerFlags int,
	proxyProtocol ProxyProtocolMode,
	connMetrics *Metrics) *Proxy {

	// A nil handle means "use the default registry" (the historical behavior);
	// callers that want to skip collection pass NilMetrics explicitly.
	if connMetrics == nil {
		connMetrics = defaultMetrics
	}

	ctx, cancel := context.WithCancel(context.Background())

	p := &Proxy{
		Listener:        listener,
		ConnectTimeout:  connectTimeout,
		CloseTimeout:    closeTimeout,
		MaxConnLifetime: maxConnLifetime,
		Dial:            dial,
		Logger:          logger,
		loggerFlags:     loggerFlags,
		proxyProtocol:   proxyProtocol,
		handlers:        &sync.WaitGroup{},
		context:         ctx,
		cancel:          cancel,
		metrics:         connMetrics,
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
func (p *Proxy) Shutdown() {
	if err := p.context.Err(); err != nil {
		// Already cancelled
		return
	}
	p.cancel()
	p.Listener.Close()
	p.handlers.Done()
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
			// Context was cancelled -- we're done here
			return
		}

		// Wait for new connection
		conn, err := p.Listener.Accept()
		if err != nil {
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

		p.handlers.Add(1)
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

			ctx, cancel := context.WithTimeout(p.context, p.ConnectTimeout)
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
				h := proxyProtoHeader(conn, tlsState, p.proxyProtocol, p.Logger)
				_, err = h.WriteTo(backend)
				if err != nil {
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
func forceHandshake(ctx context.Context, conn net.Conn, m *Metrics) error {
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

	// If set by user, set max conn lifetime for client/backend.
	if p.MaxConnLifetime > 0 {
		setDeadline(client, p.MaxConnLifetime)
		setDeadline(backend, p.MaxConnLifetime)
	}

	// For TCP and UNIX sockets, copyData calls closeRead and closeWrite for the
	// src/dst respectively. For TCP sockets, this will call the shutdown syscall
	// to block read/writes (and send a FIN packet). However, we still need to
	// free up the FDs after we're done by calling close.
	defer func() {
		_ = client.Close()
		_ = backend.Close()
	}()

	returnedC := make(chan int64)
	go func() {
		returnedC <- p.copyData(client, backend)
	}()
	forwarded := p.copyData(backend, client)
	returned := <-returnedC

	p.logConnectionMessage("closed", client, backend, forwarded, returned, start)
}

// Copy data between two connections
func (p *Proxy) copyData(dst net.Conn, src net.Conn) (written int64) {
	// When we're done copying the data, we close the read/write sides of the
	// src/dst respectively. This uses the shutdown system call to send a FIN
	// packet to the other end of the connection. By only closing the read/write
	// sides specifically, we retain the ability to forward or return data in a
	// case where a client has only half-closed the connection.
	//
	// We also set a deadline on the entire connection in order to avoid resource
	// leaks. Without the deadline, a misbehaving client could keep a connection
	// open by not reading/writing any data on their end, which would cause the
	// other copyData Go routine to wait forever. Setting a deadline forces the
	// other Go routine to unblock and return with an i/o timeout error. We could
	// also solve this by by monitoring for POLLHUP but doing so would tie up an
	// OS thread.
	//
	// See: https://github.com/golang/go/issues/67337#issuecomment-2123352634
	defer func() {
		closeRead(src)
		closeWrite(dst)
		setDeadline(src, p.CloseTimeout)
		setDeadline(dst, p.CloseTimeout)
	}()

	// Get a buffer for copy from the pool of shared buffers, to reduce allocs.
	buf := p.pool.Get().(*[]byte)
	defer p.pool.Put(buf)

	// Note: We wrap src and dst in io.Writer and io.Reader structs respectively,
	// to hide the WriteTo and ReadFrom functions on TCPConn and UnixConn.
	//
	// Why do we do this? Because CopyBuffer will prefer calling WriteTo/ReadFrom
	// if possible, in order to use splice or sendfile for better perf. However,
	// this fails if one of the arguments is tls.Conn, because TLS connections
	// have to go through user space to perform cryptographic operations.
	//
	// But this creates a problem: If splice/sendfile fail, then to still perform
	// the copy the stdlib will recursively call io.Copy. But in doing so it
	// can't provide the buffer we've allocated and thus it allocates a new one,
	// throwing away the original buf we passed in. To avoid this, we hide the
	// WriteTo and ReadFrom methods.
	//
	// Note that this is not easy to catch in testing: You might be tempted to
	// use net.Pipe() for tests, but pipes don't implement WriteTo/ReadFrom and
	// thus won't run into this issue.
	//
	// See: https://github.com/golang/go/issues/16474
	// See: https://github.com/golang/go/issues/67074
	written, err := io.CopyBuffer(
		struct{ io.Writer }{dst},
		struct{ io.Reader }{src},
		*buf)

	if err != nil && !isClosedConnectionError(err) {
		// We don't log individual "read from closed connection" errors, because
		// we already have a log statement showing that a pipe has been closed.
		if isTimeoutError(err) {
			p.metrics.ConnTimeoutCounter.Inc(1)
		}
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
	// Abrupt peer termination (RST / broken pipe) is routine for a proxy —
	// impatient clients, health checks, and idle keep-alive resets all cause
	// it — and is not actionable, so treat it the same as an orderly close.
	// errors.Is unwraps net.OpError, so these match whether or not the error
	// is wrapped in one. Both errnos are defined on Unix and Windows.
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}

	opErr := &net.OpError{}
	if errors.As(err, &opErr) {
		return (opErr.Op == "read" || opErr.Op == "readfrom" || opErr.Op == "write" || opErr.Op == "writeto") &&
			strings.Contains(err.Error(), "closed network connection")
	}
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
		// and let the CloseTimeout deadline (set by copyData's defer) unblock
		// and reap the connection. Closing it here would kill the opposite
		// (still-live) write direction, dropping in-flight return traffic.
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

func setDeadline(conn net.Conn, timeout time.Duration) {
	_ = conn.SetDeadline(time.Now().Add(timeout))
}
