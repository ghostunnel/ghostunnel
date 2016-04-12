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
	"syscall"
	"time"
)

// signalHandler for server mode. Listens for incoming SIGTERM or SIGUSR1
// signals. If we get SIGTERM, stop listening for new connections and gracefully
// terminate the process. If we get SIGUSR1, reload certificates.
func serverSignalHandler(listener net.Listener, statusListener net.Listener, stopper chan bool, context *Context) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGTERM)
	defer func() {
		stopper <- true
		signal.Stop(signals)
		listener.Close()
		if statusListener != nil {
			statusListener.Close()
		}
	}()

	for {
		// Wait for a signal
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGTERM:
				logger.Printf("received SIGTERM, stopping listener")
				time.AfterFunc(*shutdownTimeout, func() {
					logger.Printf("graceful shutdown timeout: exiting")
					exitFunc(1)
				})
				return

			case syscall.SIGUSR1:
				logger.Printf("received SIGUSR1, reloading listener")
				if serverReloadListener(context) {
					return
				}
			}
		case _ = <-context.watcher:
			logger.Printf("reloading listener...")
			if serverReloadListener(context) {
				return
			}
		}
	}
}

// Create a new listener
func serverReloadListener(context *Context) bool {
	context.listeners.Add(1)
	context.status.Reloading()
	started := make(chan bool, 1)
	go serverListen(started, context)

	// Wait for new listener to complete startup and return status
	up := <-started
	if !up {
		context.status.Listening()
		logger.Printf("failed to reload certificates")
	}
	return up
}

// signalHandler for client mode. Listens for incoming SIGTERM or SIGUSR1
// signals. If we get SIGTERM, stop listening for new connections and gracefully
// terminate the process. If we get SIGUSR1, reload certificates.
func clientSignalHandler(listener net.Listener, reloadClient chan bool, stopper chan bool, reloadStatus chan bool, context *Context) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1, syscall.SIGTERM)
	for {
		select {
		case sig := <-signals:
			switch sig {
			case syscall.SIGTERM:
				logger.Printf("received SIGTERM, stopping listener")
				time.AfterFunc(*shutdownTimeout, func() {
					logger.Printf("graceful shutdown timeout: exiting")
					exitFunc(1)
				})
				signal.Stop(signals)
				stopper <- true
				listener.Close()
				return

			case syscall.SIGUSR1:
				logger.Printf("received SIGUSR1, reloading client")
				reloadClient <- true
				reloadStatus <- true
			}
		case _ = <-context.watcher:
			logger.Printf("reloading client...")
			reloadClient <- true
			reloadStatus <- true
		}
	}
}
