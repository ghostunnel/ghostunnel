package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// sigtermHandler listenes for incoming SIGTERM signals. If received, we
// stop listening for new connections and gracefully terminate the process.
func sigtermHandler(listener net.Listener, stopper chan bool) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGTERM)

	// Wait for SIGTERM
	<-signals

	log.Printf("Got SIGTERM, closing listening socket")

	// Tell other Go routines to stop accepting connections and shut down.
	stopper <- true

	// Stop listening for SIGTERM. This way a second SIGTERM will force the
	// process the quit even if we're not done yet.
	signal.Stop(signals)

	listener.Close()
}

// sigusr1Handler listenes for incoming SIGUSR1 signals. If received, we
// reload the process by spawning a child via reexec().
func sigusr1Handler() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)

	for {
		// Wait for SIGUSR1
		<-signals

		log.Printf("Received SIGUSR1, attempting restart")
		go reexec()
	}
}
