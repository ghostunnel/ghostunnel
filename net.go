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
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rcrowley/go-metrics"
)

type proxy struct {
	quit           int32
	listener       net.Listener
	handlers       *sync.WaitGroup
	connectTimeout time.Duration
	dial           func() (net.Conn, error)
}

var (
	openCounter    = metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	totalCounter   = metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter = metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter   = metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	timeoutCounter = metrics.GetOrRegisterCounter("accept.timeout", metrics.DefaultRegistry)
	handshakeTimer = metrics.GetOrRegisterTimer("conn.handshake", metrics.DefaultRegistry)
	connTimer      = metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)
)

// Accept incoming connections in server mode and spawn Go routines to handle them.
// The signal handler (serverSignalHandle) can close the listener socket and
// send true to the stopper channel. When that happens, we stop accepting new
// connections and wait for outstanding connections to end.
func (p *proxy) accept() {
	for {
		// Wait for new connection
		conn, err := p.listener.Accept()
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

			err := forceHandshake(p.connectTimeout, conn)
			if err != nil {
				errorCounter.Inc(1)
				logger.Printf("error on TLS handshake from %s: %s", conn.RemoteAddr(), err)
				return
			}

			backend, err := p.dial()
			if err != nil {
				logger.Printf("%s", err)
				return
			}

			successCounter.Inc(1)
			p.handlers.Add(1)
			defer p.handlers.Done()
			fuse(conn, backend)
		})
	}
}

// Force handshake. Handshake usually happens on first read/write, but we
// want to force it to make sure we can control the timeout for it.
// Otherwise, unauthenticated clients would be able to open connections
// and leave them hanging forever. Going through the handshake verifies
// that clients have a valid client cert and are allowed to talk to us.
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
func fuse(client, backend net.Conn) {
	// Copy from client -> backend, and from backend -> client
	go func() { copyData(client, backend) }()
	copyData(backend, client)
}

// Copy data between two connections
func copyData(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	defer logger.Printf("closed pipe: %s:%s <- %s:%s", dst.RemoteAddr().Network(), dst.RemoteAddr().String(), src.RemoteAddr().Network(), src.RemoteAddr().String())
	logger.Printf("opening pipe: %s:%s <- %s:%s", dst.RemoteAddr().Network(), dst.RemoteAddr().String(), src.RemoteAddr().Network(), src.RemoteAddr().String())

	_, err := io.Copy(dst, src)

	if err != nil {
		logger.Printf("%s", err)
	}
}

// Parse a string representing a TCP address or UNIX socket for our backend
// target. The input can be or the form "HOST:PORT" for TCP or "unix:PATH"
// for a UNIX socket.
func parseUnixOrTCPAddress(input string) (network, address, host string, err error) {
	if strings.HasPrefix(input, "unix:") {
		network = "unix"
		address = input[5:]
		return
	}

	host, _, err = net.SplitHostPort(input)
	if err != nil {
		return
	}

	// Make sure target address resolves
	_, err = net.ResolveTCPAddr("tcp", input)
	if err != nil {
		return
	}

	network, address = "tcp", input
	return
}
