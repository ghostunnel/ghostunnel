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
	"fmt"
	"log"
	"log/syslog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/kavu/go_reuseport"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	listenAddress  = kingpin.Flag("listen", "Address and port to listen on.").PlaceHolder("ADDR").Required().TCP()
	forwardAddress = kingpin.Flag("target", "Address to foward connections to (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	unsafeTarget   = kingpin.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1 or ::1").Bool()
	keystorePath   = kingpin.Flag("keystore", "Path to certificate and keystore (PKCS12).").PlaceHolder("PATH").Required().String()
	keystorePass   = kingpin.Flag("storepass", "Password for certificate and keystore.").PlaceHolder("PASS").String()
	caBundlePath   = kingpin.Flag("cacert", "Path to certificate authority bundle file (PEM/X509).").Required().String()
	timedReload    = kingpin.Flag("timed-reload", "Reload keystores every N seconds, refresh listener on changes.").PlaceHolder("N").Int()
	allowAll       = kingpin.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	allowedCNs     = kingpin.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	allowedOUs     = kingpin.Flag("allow-ou", "Allow clients with organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	pprofAddress   = kingpin.Flag("pprof", "Enable net/http/pprof on given host:port for profiling").PlaceHolder("ADDR").TCP()
	useSyslog      = kingpin.Flag("syslog", "Send logs to syslog instead of stderr.").Bool()
)

// Global logger instance
var logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)

func initLogger() {
	if *useSyslog {
		var err error
		logger, err = syslog.NewLogger(syslog.LOG_NOTICE|syslog.LOG_DAEMON, log.LstdFlags|log.Lmicroseconds)
		panicOnError(err)
	}

	// Set log prefix to process ID to distinguish parent/child
	logger.SetPrefix(fmt.Sprintf("[%5d] ", os.Getpid()))
}

// panicOnError panics if err is not nil
func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	kingpin.Parse()

	// Validate flags
	if !(*allowAll) && len(*allowedCNs) == 0 && len(*allowedOUs) == 0 {
		fmt.Fprintf(os.Stderr, "ghostunnel: error: at least one of --allow-all, --allow-cn or --allow-ou is required")
		os.Exit(1)
	}
	if *allowAll && len(*allowedCNs) != 0 {
		fmt.Fprintf(os.Stderr, "ghostunnel: error: --allow-all and --allow-cn are mutually exclusive")
		os.Exit(1)
	}
	if *allowAll && len(*allowedOUs) != 0 {
		fmt.Fprintf(os.Stderr, "ghostunnel: error: --allow-all and --allow-ou are mutually exclusive")
		os.Exit(1)
	}
	if !validateTarget(*forwardAddress) {
		fmt.Fprintf(os.Stderr, "ghostunnel: error: --target must be localhost:port, 127.0.0.1:port or [::1]:port")
		os.Exit(1)
	}

	initLogger()

	if *pprofAddress != nil {
		addr := (*pprofAddress).String()
		logger.Printf("profiling enabled; running pprof on http://%s/debug/pprof", addr)
		go func() {
			logger.Fatal(http.ListenAndServe(addr, nil))
		}()
	}

	listeners := &sync.WaitGroup{}
	listeners.Add(1)

	// Set up file watchers (if requested)
	watcher := make(chan bool, 1)
	if *timedReload > 0 {
		go watchFiles([]string{*keystorePath, *caBundlePath}, time.Duration(*timedReload)*time.Second, watcher)
	}

	// A channel to notify us that the listener is running.
	started := make(chan bool, 1)
	go listen(started, listeners, watcher)

	up := <-started
	if !up {
		logger.Print("failed to start initial listener")
		os.Exit(1)
	}

	logger.Print("initial startup completed, waiting for connections")
	listeners.Wait()
	logger.Print("all listeners closed, shutting down")
}

func validateTarget(addr string) bool {
	if *unsafeTarget {
		return true
	}
	if strings.HasPrefix(addr, "unix:") {
		return true
	}
	if strings.HasPrefix(addr, "127.0.0.1:") {
		return true
	}
	if strings.HasPrefix(addr, "[::1]:") {
		return true
	}
	if strings.HasPrefix(addr, "localhost:") {
		return true
	}
	return false
}

// Open listening socket. Take note that we create a "reusable port
// listener", meaning we pass SO_REUSEPORT to the kernel. This allows
// us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purposes of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is
// expiring.
func listen(started chan bool, listeners *sync.WaitGroup, watcher chan bool) {
	// Open raw listening socket
	network, address := decodeAddress(*listenAddress)
	rawListener, err := reuseport.NewReusablePortListener(network, address)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		started <- false
		return
	}

	// Wrap listening socket with TLS listener.
	tlsConfig, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath)
	if err != nil {
		logger.Printf("error setting up TLS: %s", err)
		started <- false
		return
	}

	leaf := tlsConfig.Certificates[0].Leaf

	listener := tls.NewListener(rawListener, tlsConfig)
	logger.Printf("listening on %s", *listenAddress)
	defer listener.Close()

	handlers := &sync.WaitGroup{}
	handlers.Add(1)

	// A channel to allow signal handlers to notify our accept loop that it
	// should shut down.
	stopper := make(chan bool, 1)

	backendNet, backendAddr, err := parseTarget(*forwardAddress)
	if err != nil {
		logger.Printf("invalid backend address: %s", err)
		started <- false
		return
	}

	dial := func() (net.Conn, error) {
		return net.Dial(backendNet, backendAddr)
	}

	go accept(listener, handlers, stopper, leaf, dial)
	go signalHandler(listener, stopper, listeners, watcher)

	started <- true

	logger.Printf("listening with cert serial no. %d (expiring %s)", leaf.SerialNumber, leaf.NotAfter.String())
	handlers.Wait()

	listeners.Done()
}
