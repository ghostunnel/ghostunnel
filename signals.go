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
	ctx "context"
	"os"
	"os/signal"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
)

// isShutdownSignal checks if the received signal is a shutdown signal
// and returns true if that's the case. Returns false if the signal is
// a refresh signal.
func isShutdownSignal(sig os.Signal) bool {
	for _, shutdownSignal := range shutdownSignals {
		if sig == shutdownSignal {
			return true
		}
	}
	return false
}

// signalHandler listens for incoming shutdown or refresh signals. If we get
// a shutdown signal, we stop listening for new connections and gracefully
// terminate the process. If we get a refresh signal, reload certificates.
func (context *Context) signalHandler(p *proxy.Proxy) {
	signals := make(chan os.Signal, 3)
	signal.Notify(signals, append(shutdownSignals, refreshSignals...)...)
	defer signal.Stop(signals)

	for {
		// Wait for a signal
		select {
		case sig := <-signals:
			if isShutdownSignal(sig) {
				logger.Printf("received %s, shutting down", sig.String())
				context.status.Stopping()

				// Best-effort graceful shutdown of status listener
				if context.statusHTTP != nil {
					go context.statusHTTP.Shutdown(ctx.Background())
				}

				// Force-exit after timeout
				time.AfterFunc(context.shutdownTimeout, func() {
					// Graceful shutdown timeout reached. If we can't drain connections
					// to exit gracefully after this timeout, let's just exit.
					logger.Printf("graceful shutdown timeout: forcing exit")
					exitFunc(1)
				})

				p.Shutdown()
				logger.Printf("shutdown proxy, waiting for drain")
				return
			}

			logger.Printf("received %s, reloading TLS configuration", sig.String())
			context.reload()
		}
	}
}

func (context *Context) reloadHandler(interval time.Duration) {
	if interval == 0 {
		return
	}
	for range time.Tick(interval) {
		context.reload()
	}
}

func (context *Context) reload() {
	context.status.Reloading()
	if err := context.tlsConfigSource.Reload(); err != nil {
		logger.Printf("error reloading TLS configuration: %s", err)
	}
	if context.regoPolicy != nil {
		if err := context.regoPolicy.Reload(); err != nil {
			logger.Printf("error reloading OPA policy: %s", err)
		}
	}
	logger.Printf("reloading configuration complete")
	context.status.Listening()
}
