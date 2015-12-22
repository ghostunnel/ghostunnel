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
	"os"
	"strings"
	"sync"
)

// Accept incoming connections and spawn Go routines to handle them.
func accept(listener net.Listener, wg *sync.WaitGroup, stopper chan bool, leaf *x509.Certificate, dial func() (net.Conn, error)) {
	defer wg.Done()
	defer listener.Close()

	for {
		// Wait for new connection
		conn, err := listener.Accept()

		if err != nil {
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
			logger.Printf("received non-TLS connection from %s? ignoring", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Force handshake. Handshake usually happens on first read/write, but
		// we want to authenticate before reading/writing so we need to force
		// the handshake to get the client cert.
		err = tlsConn.Handshake()
		if err != nil {
			logger.Printf("failed TLS handshake on %s: %s", conn.RemoteAddr(), err)
			conn.Close()
			continue
		}

		if !authorized(tlsConn.ConnectionState()) {
			logger.Printf("rejecting connection from %s: bad client certificate", conn.RemoteAddr())
			conn.Close()
			continue
		}

		wg.Add(1)
		go handle(conn, wg, dial)
	}
}

// Handle incoming connection by opening new connection to our backend service
// and fusing them together.
func handle(conn net.Conn, wg *sync.WaitGroup, dial func() (net.Conn, error)) {
	defer wg.Done()
	defer conn.Close()

	logger.Printf("successful handshake with %s", conn.RemoteAddr())

	backend, err := dial()

	if err != nil {
		logger.Printf("failed to dial backend: %s", err)
		return
	}

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

// Parse a string representing a TCP address or UNIX socket for our backend
// target. The input can be or the form "HOST:PORT" for TCP or "unix:PATH"
// for a UNIX socket.
func parseTarget(input string) (network, address string, err error) {
	if strings.HasPrefix(input, "unix:") {
		network = "unix"
		address = input[5:]
		_, err = os.Stat(address)
		return
	}

	var tcp *net.TCPAddr
	tcp, err = net.ResolveTCPAddr("tcp", input)
	if err != nil {
		return
	}

	network, address = tcp.Network(), tcp.String()
	return
}
