package main

import (
	"crypto/tls"
	"io"
	"net"
	"sync"
)

// Accept incoming connections and spawn Go routines to handle them.
func accept(listener net.Listener, wg *sync.WaitGroup, stopper chan bool) {
	defer wg.Done()
	defer listener.Close()

	for {
		// Check if we're supposed to stop
		select {
		case _ = <-stopper:
			return
		default:
		}

		// Wait for new connection
		conn, err := listener.Accept()

		if err != nil {
			logger.Printf("error accepting connection: %s", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			logger.Printf("received non-TLS connection from %s? Ignoring", conn.RemoteAddr())
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

		if !authorized(tlsConn) {
			logger.Printf("rejecting connection from %s: bad client certificate", conn.RemoteAddr())
			conn.Close()
			continue
		}

		wg.Add(1)
		go handle(conn, wg)
	}

	logger.Printf("closing listening socket")
}

// Handle incoming connection by opening new connection to our backend service
// and fusing them together.
func handle(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	logger.Printf("incoming connection: %s", conn.RemoteAddr())

	backend, err := dialBackend()
	defer backend.Close()

	if err != nil {
		logger.Printf("failed to dial backend: %s", err)
		return
	}

	fuse(conn, backend)
}

// Fuse connections together
func fuse(client, backend net.Conn) {
	go func() { copyData(client, backend) }()
	copyData(backend, client)
}

func copyData(dst net.Conn, src net.Conn) {
	defer logger.Printf("closed pipe: %s <- %s", dst.RemoteAddr(), src.RemoteAddr())
	logger.Printf("opening pipe: %s <- %s", dst.RemoteAddr(), src.RemoteAddr())

	_, err := io.Copy(dst, src)

	if err != nil {
		logger.Printf("%s", err)
	}
}

func dialBackend() (net.Conn, error) {
	return net.Dial((*forwardAddress).Network(), (*forwardAddress).String())
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
