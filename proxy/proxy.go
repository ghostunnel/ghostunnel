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
	"crypto/tls"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
)

var (
	openCounter    = metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	totalCounter   = metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter = metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter   = metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	timeoutCounter = metrics.GetOrRegisterCounter("accept.timeout", metrics.DefaultRegistry)
	handshakeTimer = metrics.GetOrRegisterTimer("conn.handshake", metrics.DefaultRegistry)
	connTimer      = metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)
)

// Logger is used by this package to log messages
type Logger interface {
	Printf(format string, v ...interface{})
}

// Dialer represents a function that can dial a backend/destination for forwarding connections.
type Dialer func() (net.Conn, error)

// Proxy will take incoming connections from a listener and forward them to
// a backend through the given dialer.
type Proxy struct {
	// Listener to accept connetions on.
	Listener net.Listener
	// ConnectTimeout after which connections are terminated.
	ConnectTimeout time.Duration
	// Dial function to reach backend to forward connections to.
	Dial Dialer
	// Logger is used to log information messages about connections, errors.
	Logger Logger

	// Internal state to indicate that we want to shut down.
	quit int32

	// Internal wait group to keep track of outstanding handlers.
	handlers *sync.WaitGroup
}

// New creates a new proxy.
func New(listener net.Listener, timeout time.Duration, dial Dialer, logger Logger) *Proxy {
	p := &Proxy{
		Listener:       listener,
		ConnectTimeout: timeout,
		Dial:           dial,
		Logger:         logger,
		quit:           0,
		handlers:       &sync.WaitGroup{},
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
	if atomic.LoadInt32(&p.quit) == 1 {
		return
	}
	atomic.StoreInt32(&p.quit, 1)
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

// Accept incoming connections and spawn Go routines to handle them and forward
// the data to the backend. Will stop accepting connections if Shutdown() is called.
// Run this in a Goroutine, call Wait() to block on proxy shutdown/connection drain.
func (p *Proxy) Accept() {
	for {
		// Wait for new connection
		conn, err := p.Listener.Accept()
		if err != nil {
			// Check if we're supposed to stop
			if atomic.LoadInt32(&p.quit) == 1 {
				return
			}

			errorCounter.Inc(1)
			continue
		}

		openCounter.Inc(1)
		totalCounter.Inc(1)

		go connTimer.Time(func() {
			defer conn.Close()
			defer openCounter.Dec(1)

			err := forceHandshake(p.ConnectTimeout, conn)
			if err != nil {
				errorCounter.Inc(1)
				p.Logger.Printf("error on TLS handshake from %s: %s", conn.RemoteAddr(), err)
				return
			}

			backend, err := p.Dial()
			if err != nil {
				p.Logger.Printf("error: %s", err)
				return
			}

			successCounter.Inc(1)
			p.handlers.Add(1)
			defer p.handlers.Done()
			p.fuse(conn, backend)
		})
	}
}

// Force handshake. Handshake usually happens on first read/write, but we want
// to force it to make sure we can control the timeout for it. Otherwise,
// unauthenticated clients would be able to open connections and leave them
// hanging forever. Going through the handshake verifies that clients have a
// valid client cert and are allowed to talk to us.
func forceHandshake(timeout time.Duration, conn net.Conn) error {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		startTime := time.Now()
		defer handshakeTimer.UpdateSince(startTime)

		// Set deadline to avoid blocking forever
		err := tlsConn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return err
		}

		err = tlsConn.Handshake()
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// If we timed out, increment timeout metric
			timeoutCounter.Inc(1)
		}

		if err != nil {
			return err
		}

		// Success: clear deadline
		err = tlsConn.SetDeadline(time.Time{})
		if err != nil {
			return err
		}
	}

	return nil
}

// Fuse connections together
func (p *Proxy) fuse(client, backend net.Conn) {
	// Copy from client -> backend, and from backend -> client
	defer p.logConnectionMessage("closed", client, backend)
	p.logConnectionMessage("opening", client, backend)

	go func() { p.copyData(client, backend) }()
	p.copyData(backend, client)
}

// Copy data between two connections
func (p *Proxy) copyData(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()

	_, err := io.Copy(dst, src)

	if err != nil {
		p.Logger.Printf("error: %s", err)
	}
}

// Log information message about connection
func (p *Proxy) logConnectionMessage(action string, dst net.Conn, src net.Conn) {
	p.Logger.Printf(
		"%s pipe: %s:%s <-> %s:%s",
		action,
		dst.RemoteAddr().Network(),
		dst.RemoteAddr().String(),
		src.RemoteAddr().Network(),
		src.RemoteAddr().String())
}
