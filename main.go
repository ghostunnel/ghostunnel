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
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cyberdelia/go-metrics-graphite"
	"github.com/kavu/go_reuseport"
	"github.com/rcrowley/go-metrics"
	"gopkg.in/alecthomas/kingpin.v2"
)

// These are initialized via -ldflags
var buildRevision = "unknown"
var buildCompiler = "unknown"

var defaultMetricsPrefix = "ghostunnel"

var (
	app            = kingpin.New("ghostunnel", "A simple SSL/TLS proxy with mutual authentication for securing non-TLS services.")
	listenAddress  = app.Flag("listen", "Address and port to listen on (HOST:PORT).").PlaceHolder("ADDR").Required().TCP()
	forwardAddress = app.Flag("target", "Address to foward connections to (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	unsafeTarget   = app.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1 or [::1].").Bool()
	keystorePath   = app.Flag("keystore", "Path to certificate and keystore (PKCS12).").PlaceHolder("PATH").Required().String()
	keystorePass   = app.Flag("storepass", "Password for certificate and keystore (optional).").PlaceHolder("PASS").String()
	caBundlePath   = app.Flag("cacert", "Path to certificate authority bundle file (PEM/X509).").Required().String()
	timedReload    = app.Flag("timed-reload", "Reload keystores every N seconds, refresh listener on changes.").PlaceHolder("N").Int()
	allowAll       = app.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	allowedCNs     = app.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	allowedOUs     = app.Flag("allow-ou", "Allow clients with organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	graphiteAddr   = app.Flag("graphite", "Collect metrics and report them to the given graphite instance (raw TCP).").PlaceHolder("ADDR").TCP()
	metricsURL     = app.Flag("metrics-url", "Collect metrics and POST them periodically to the given URL (via HTTP/JSON).").PlaceHolder("URL").String()
	metricsPrefix  = app.Flag("metrics-prefix", fmt.Sprintf("Set prefix string for all reported metrics (default: %s).", defaultMetricsPrefix)).PlaceHolder("PREFIX").Default(defaultMetricsPrefix).String()
	statusAddr     = app.Flag("status", "Enable serving /_status and /_metrics on given HOST:PORT (shows tunnel/backend health status).").PlaceHolder("ADDR").TCP()
	enableProf     = app.Flag("enable-pprof", "Enable serving /debug/pprof endpoints alongside /_status (for profiling).").Bool()
	useSyslog      = app.Flag("syslog", "Send logs to syslog instead of stderr.").Bool()
)

// Context groups listening context data together
type Context struct {
	watcher   chan bool
	listeners *sync.WaitGroup
	status    *statusHandler
	dial      func() (net.Conn, error)
	metrics   *metricsConfig
}

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

// Validate flags
func validateFlags(app *kingpin.Application) error {
	if !(*allowAll) && len(*allowedCNs) == 0 && len(*allowedOUs) == 0 {
		return fmt.Errorf("at least one of --allow-all, --allow-cn or --allow-ou is required")
	}
	if *allowAll && len(*allowedCNs) != 0 {
		return fmt.Errorf("--allow-all and --allow-cn are mutually exclusive")
	}
	if *allowAll && len(*allowedOUs) != 0 {
		return fmt.Errorf("--allow-all and --allow-ou are mutually exclusive")
	}
	if *enableProf && *statusAddr == nil {
		return fmt.Errorf("--enable-pprof requires --status to be set")
	}
	if !validateTarget(*forwardAddress) {
		return fmt.Errorf("--target must be localhost:port, 127.0.0.1:port or [::1]:port")
	}
	if *metricsURL != "" && !strings.HasPrefix(*metricsURL, "http://") && !strings.HasPrefix(*metricsURL, "https://") {
		return fmt.Errorf("--metrics-url should start with http:// or https://")
	}
	return nil
}

func main() {
	initLogger()
	runtime.GOMAXPROCS(runtime.NumCPU())

	app.Version(fmt.Sprintf("rev %s built with %s", buildRevision, buildCompiler))
	app.Validate(validateFlags)

	if len(os.Args) == 1 {
		fmt.Fprintf(os.Stderr, "error: no flags provided, try --help\n")
		os.Exit(1)
	}

	_, err := app.Parse(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s, try --help\n", err)
		os.Exit(1)
	}

	err, dial := backendDialer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid backend address: %s", err)
		os.Exit(1)
	}

	if *graphiteAddr != nil {
		go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *graphiteAddr)
	}

	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to get hostname: %s", err)
		os.Exit(1)
	}

	metrics := &metricsConfig{
		url:      *metricsURL,
		registry: metrics.DefaultRegistry,
		prefix:   *metricsPrefix,
		hostname: hostname,
	}

	if metrics.url != "" {
		go metrics.publishMetrics()
	}

	listeners := &sync.WaitGroup{}
	listeners.Add(1)

	// Set up file watchers (if requested)
	watcher := make(chan bool, 1)
	if *timedReload > 0 {
		go watchFiles([]string{*keystorePath, *caBundlePath}, time.Duration(*timedReload)*time.Second, watcher)
	}

	status := newStatusHandler(dial)
	context := &Context{watcher, listeners, status, dial, metrics}

	// Start listening
	started := make(chan bool, 1)
	go listen(started, context)

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
func listen(started chan bool, context *Context) {
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

	var statusListener net.Listener
	if *statusAddr != nil {
		statusListener = serveStatus(*tlsConfig, context)
	}

	listener := tls.NewListener(rawListener, tlsConfig)
	logger.Printf("listening on %s", *listenAddress)
	defer listener.Close()

	handlers := &sync.WaitGroup{}
	handlers.Add(1)

	// A channel to allow signal handlers to notify our accept loop that it
	// should shut down.
	stopper := make(chan bool, 1)

	go accept(listener, handlers, stopper, leaf, context.dial)
	go signalHandler(listener, statusListener, stopper, context)

	started <- true
	context.status.Listening()

	logger.Printf("listening with cert serial no. %d (expiring %s)", leaf.SerialNumber, leaf.NotAfter.String())
	handlers.Wait()

	context.listeners.Done()
}

// Serve /_status (if configured)
func serveStatus(tlsConfig tls.Config, context *Context) net.Listener {
	mux := http.NewServeMux()
	mux.Handle("/_status", context.status)
	mux.Handle("/_metrics", context.metrics)
	if *enableProf {
		mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}

	network, address := decodeAddress(*statusAddr)
	rawListener, err := reuseport.NewReusablePortListener(network, address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to bind on status port: %s", err)
		os.Exit(1)
	}

	// Disable client certs for /_status port
	tlsConfig.ClientAuth = tls.NoClientCert

	listener := tls.NewListener(rawListener, &tlsConfig)
	logger.Printf("status port enabled; serving status on https://%s/_status", address)
	go func() {
		server := &http.Server{
			Handler:  mux,
			ErrorLog: logger,
		}
		server.Serve(listener)
	}()

	return listener
}

// Get backend dialer function
func backendDialer() (error, func() (net.Conn, error)) {
	backendNet, backendAddr, err := parseTarget(*forwardAddress)
	if err != nil {
		return err, nil
	}

	return nil, func() (net.Conn, error) {
		return net.Dial(backendNet, backendAddr)
	}
}
