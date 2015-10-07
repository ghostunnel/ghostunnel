package main

import (
	"crypto/tls"
	"io"
	"log"
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
			log.Printf("Error accepting connection: %s", err)
			continue
		}

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			log.Printf("Received non-TLS connection? Ignoring")
			conn.Close()
			continue
		}

		if !authorized(tlsConn) {
			log.Printf("Rejecting connection, bad client certificate")
			conn.Close()
			continue
		}

		wg.Add(1)
		go handle(conn, wg)
	}

	log.Printf("Closing listening socket")
}

// Handle incoming connection by opening new connection to our backend service
// and fusing them together.
func handle(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	log.Printf("Incoming connection: %s", conn.RemoteAddr())

	backend, err := dialBackend()
	defer backend.Close()

	if err != nil {
		log.Printf("Failed to dial backend: %s", err)
		return
	}

	fuse(conn, backend)
}

// Fuse connections together
func fuse(client, backend net.Conn) {
	defer log.Printf("Closed pipe: %s <-> %s", client.RemoteAddr(), backend.RemoteAddr())
	log.Printf("Opening pipe: %s <-> %s", client.RemoteAddr(), backend.RemoteAddr())

	go func() {
		forwardData(client, backend)
	}()

	forwardData(backend, client)
}

func forwardData(dst net.Conn, src net.Conn) {
	_, err := io.Copy(dst, src)

	if err != nil {
		log.Printf("Error from pipe %s <- (%s)", dst.RemoteAddr(), src.RemoteAddr(), err)
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
