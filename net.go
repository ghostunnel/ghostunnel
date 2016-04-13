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
	quit     int32
	listener net.Listener
	handlers *sync.WaitGroup

	authorize func(net.Conn) bool
	dial      func() (net.Conn, error)
}

var (
	openCounter    = metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	totalCounter   = metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter = metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter   = metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	timeoutCounter = metrics.GetOrRegisterCounter("accept.timeout", metrics.DefaultRegistry)
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
		logger.Printf("incoming connection from %s", conn.RemoteAddr())

		go connTimer.Time(func() {
			defer conn.Close()
			defer openCounter.Dec(1)

			if !p.authorize(conn) {
				logger.Printf("rejecting unauthorized connection from %s", conn.RemoteAddr())
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

func authorize(conn net.Conn) bool {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return false
	}

	// Force handshake. Handshake usually happens on first read/write, but
	// we want to authenticate before reading/writing so we need to force
	// the handshake to get the client cert. If handshake blocks for more
	// than the timeout, we kill the connection.
	timer := time.AfterFunc(*timeoutDuration, func() {
		logger.Printf("timed out TLS handshake on %s", conn.RemoteAddr())
		conn.SetDeadline(time.Now())
		conn.Close()
		timeoutCounter.Inc(1)
	})

	err := tlsConn.Handshake()
	timer.Stop()
	if err != nil {
		logger.Printf("failed TLS handshake on %s: %s", conn.RemoteAddr(), err)
		errorCounter.Inc(1)
		return false
	}

	return authorized(tlsConn.ConnectionState())
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

// Helper function to decode a *net.TCPAddr into a tuple of network and
// address. Must use this since kavu/so_reuseport does not currently
// support passing "tcp" to support for IPv4 and IPv6. We must pass "tcp4"
// or "tcp6" explicitly.
func decodeAddress(tuple *net.TCPAddr) (network, address string) {
	if tuple.IP.To4() != nil {
		network = "tcp4"
	} else {
		network = "tcp6"
	}

	address = tuple.String()
	return
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

	var tcp *net.TCPAddr
	tcp, err = net.ResolveTCPAddr("tcp", input)
	if err != nil {
		return
	}

	network, address = decodeAddress(tcp)
	return
}
