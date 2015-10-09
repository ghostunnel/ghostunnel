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
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// signalHandler listenes for incoming SIGTERM or SIGUSR1 signals. If we get
// SIGTERM, stop listening for new connections and gracefully terminate the
// process.  If we get SIGUSR1, reload certificates.
func signalHandler(listener net.Listener, stopper chan bool, listeners *sync.WaitGroup, watcher chan bool) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)
	defer func() {
		stopper <- true
		signal.Stop(signals)
		listener.Close()
	}()

	for {
		// Wait for a signal
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGTERM:
				logger.Printf("received SIGTERM, stopping listener")
				return

			case syscall.SIGUSR1:
				logger.Printf("received SIGUSR1, reloading listener")
				if reloadListener(listeners, watcher) {
					return
				}
			}
		case _ = <-watcher:
			logger.Printf("detected file change, reloading listener")
			if reloadListener(listeners, watcher) {
				return
			}
		}
	}
}

// Create a new listener
func reloadListener(listeners *sync.WaitGroup, watcher chan bool) bool {
	listeners.Add(1)
	started := make(chan bool, 1)
	go listen(started, listeners, watcher)

	// Wait for new listener to complete startup and return status
	up := <-started
	if !up {
		logger.Printf("failed to reload certificates")
	}
	return up
}
