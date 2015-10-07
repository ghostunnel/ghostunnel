package main

import (
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
		conn, err := listener.Accept()

		// Check if we're supposed to stop
		select {
		case _ = <-stopper:
			return
		default:
		}

		if err != nil {
			log.Printf("Error accepting connection: %s", err)
			continue
		}

		wg.Add(1)
		go handle(conn, wg)
	}

	log.Printf("Closing listening socket")
}

// Handle incoming connection by opening new connection to our backend service
// fusing them together.
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
