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
	"crypto/x509"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/rcrowley/go-metrics"
)

// Accept incoming connections in server mode and spawn Go routines to handle them.
// The signal handler (serverSignalHandle) can close the listener socket and
// send true to the stopper channel. When that happens, we stop accepting new
// connections and wait for outstanding connections to end.
func serverAccept(listener net.Listener, wg *sync.WaitGroup, stopper chan bool, leaf *x509.Certificate, dial func() (net.Conn, error)) {
	defer wg.Done()
	// TODO: defer listener.Close() is redundant because serverSignalHandler closes
	// the socket.
	defer listener.Close()

	openCounter := metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	totalCounter := metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter := metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter := metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	timer := metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)

	for {
		// Wait for new connection
		conn, err := listener.Accept()
		openCounter.Inc(1)
		totalCounter.Inc(1)

		if err != nil {
			openCounter.Dec(1)
			errorCounter.Inc(1)

			// Check if we're supposed to stop
			select {
			case _ = <-stopper:
				logger.Printf("closing socket with cert serial no. %d (expiring %s)", leaf.SerialNumber, leaf.NotAfter.String())
				return
			default:
			}

			logger.Printf("error accepting connection: %s", err)
			continue
		}

		logger.Printf("incoming connection: %s", conn.RemoteAddr())

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			openCounter.Dec(1)
			errorCounter.Inc(1)
			logger.Printf("received non-TLS connection from %s? ignoring", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Force handshake. Handshake usually happens on first read/write, but
		// we want to authenticate before reading/writing so we need to force
		// the handshake to get the client cert.
		err = tlsConn.Handshake()
		if err != nil {
			openCounter.Dec(1)
			errorCounter.Inc(1)
			logger.Printf("failed TLS handshake on %s: %s", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}

		if !authorized(tlsConn.ConnectionState()) {
			openCounter.Dec(1)
			errorCounter.Inc(1)
			logger.Printf("rejecting connection from %s: bad client certificate", conn.RemoteAddr())
			conn.Close()
			continue
		}

		logger.Printf("successful handshake with %s", conn.RemoteAddr())

		wg.Add(1)
		go timer.Time(func() {
			defer wg.Done()
			defer conn.Close()
			defer openCounter.Dec(1)
			handle(conn, successCounter, errorCounter, dial)
		})
	}
}

// Accept incoming connections in client mode and spawn Go routines to handle them.
func clientAccept(listener net.Listener, stopper chan bool, dial func() (net.Conn, error)) {
	// TODO: defer listener.Close() is redundant because serverSignalHandler closes
	// the socket.
	defer listener.Close()

	openCounter := metrics.GetOrRegisterCounter("conn.open", metrics.DefaultRegistry)
	totalCounter := metrics.GetOrRegisterCounter("accept.total", metrics.DefaultRegistry)
	successCounter := metrics.GetOrRegisterCounter("accept.success", metrics.DefaultRegistry)
	errorCounter := metrics.GetOrRegisterCounter("accept.error", metrics.DefaultRegistry)
	timer := metrics.GetOrRegisterTimer("conn.lifetime", metrics.DefaultRegistry)

	handlers := &sync.WaitGroup{}

	for {
		// Wait for new connection
		conn, err := listener.Accept()
		openCounter.Inc(1)
		totalCounter.Inc(1)

		if err != nil {
			openCounter.Dec(1)
			errorCounter.Inc(1)

			// Check if we're supposed to stop
			select {
			case _ = <-stopper:
				logger.Printf("closing listening socket")
				// wait for all the connects to end
				handlers.Wait()
				return
			default:
			}

			logger.Printf("error accepting connection: %s", err)
			continue
		}

		logger.Printf("incoming connection: %s", conn.RemoteAddr())

		handlers.Add(1)
		go timer.Time(func() {
			defer handlers.Done()
			defer conn.Close()
			defer openCounter.Dec(1)
			handle(conn, successCounter, errorCounter, dial)
		})
	}
}

// Handle incoming connection by opening new connection to our backend service
// and fusing them together.
func handle(conn net.Conn, successCounter metrics.Counter, errorCounter metrics.Counter, dial func() (net.Conn, error)) {
	backend, err := dial()

	if err != nil {
		errorCounter.Inc(1)
		logger.Printf("failed to dial backend: %s", err)
		return
	}

	successCounter.Inc(1)
	fuse(conn, backend)
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
