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
	"github.com/square/go-sq-metrics"
	"gopkg.in/alecthomas/kingpin.v2"
)

// These are initialized via -ldflags
var buildRevision = "unknown"
var buildCompiler = "unknown"

var defaultMetricsPrefix = "ghostunnel"
var defaultMinTLSVersion = "1.2"

var (
	app = kingpin.New("ghostunnel", "A simple SSL/TLS proxy with mutual authentication for securing non-TLS services.")

	serverCommand        = app.Command("server", "Server mode (TLS listener -> plain TCP/UNIX target).")
	serverListenAddress  = serverCommand.Flag("listen", "Address and port to listen on (HOST:PORT).").PlaceHolder("ADDR").Required().TCP()
	serverForwardAddress = serverCommand.Flag("target", "Address to forward connections to (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	serverUnsafeTarget   = serverCommand.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	serverAllowAll       = serverCommand.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	serverAllowedCNs     = serverCommand.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	serverAllowedOUs     = serverCommand.Flag("allow-ou", "Allow clients with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	serverAllowedDNSs    = serverCommand.Flag("allow-dns-san", "Allow clients with given DNS subject alternative name (can be repeated).").PlaceHolder("SAN").Strings()
	serverAllowedIPs     = serverCommand.Flag("allow-ip-san", "Allow clients with given IP subject alternative name (can be repeated).").PlaceHolder("SAN").IPList()

	clientCommand       = app.Command("client", "Client mode (plain TCP/UNIX listener -> TLS target).")
	clientListenAddress = clientCommand.Flag("listen", "Address and port to listen on (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	// Note: can't use .TCP() for clientForwardAddress because we need to set the original string in tls.Config.ServerName.
	clientForwardAddress = clientCommand.Flag("target", "Address to forward connections to (HOST:PORT).").PlaceHolder("ADDR").Required().String()
	clientUnsafeListen   = clientCommand.Flag("unsafe-listen", "If set, does not limit listen to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()

	keystorePath  = app.Flag("keystore", "Path to certificate and keystore (PKCS12).").PlaceHolder("PATH").Required().String()
	keystorePass  = app.Flag("storepass", "Password for certificate and keystore (optional).").PlaceHolder("PASS").String()
	caBundlePath  = app.Flag("cacert", "Path to certificate authority bundle file (PEM/X509).").Required().String()
	tlsVersion    = app.Flag("min-tls", fmt.Sprintf("Set the minimum required TLS version (1.0, 1.1, 1.2; default: %s).", defaultMinTLSVersion)).Default(defaultMinTLSVersion).PlaceHolder("X.Y").String()
	timedReload   = app.Flag("timed-reload", "Reload keystores every N seconds, refresh listener/client on changes.").PlaceHolder("N").Int()
	graphiteAddr  = app.Flag("graphite", "Collect metrics and report them to the given graphite instance (raw TCP).").PlaceHolder("ADDR").TCP()
	metricsURL    = app.Flag("metrics-url", "Collect metrics and POST them periodically to the given URL (via HTTP/JSON).").PlaceHolder("URL").String()
	metricsPrefix = app.Flag("metrics-prefix", fmt.Sprintf("Set prefix string for all reported metrics (default: %s).", defaultMetricsPrefix)).PlaceHolder("PREFIX").Default(defaultMetricsPrefix).String()
	statusAddr    = app.Flag("status", "Enable serving /_status and /_metrics on given HOST:PORT (shows tunnel/backend health status).").PlaceHolder("ADDR").TCP()
	enableProf    = app.Flag("enable-pprof", "Enable serving /debug/pprof endpoints alongside /_status (for profiling).").Bool()
	useSyslog     = app.Flag("syslog", "Send logs to syslog instead of stderr.").Bool()
)

// Context groups listening context data together
type Context struct {
	watcher   chan bool
	listeners *sync.WaitGroup
	status    *statusHandler
	dial      func() (net.Conn, error)
	metrics   *sqmetrics.SquareMetrics
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

// Validate flags for both, server and client mode
func validateFlags(app *kingpin.Application) error {
	if *enableProf && *statusAddr == nil {
		return fmt.Errorf("--enable-pprof requires --status to be set")
	}
	if *metricsURL != "" && !strings.HasPrefix(*metricsURL, "http://") && !strings.HasPrefix(*metricsURL, "https://") {
		return fmt.Errorf("--metrics-url should start with http:// or https://")
	}
	return nil
}

// Validates that addr is either a unix socket or localhost
func validateUnixOrLocalhost(addr string) bool {
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

// Validate flags for server mode
func serverValidateFlags() error {
	if !(*serverAllowAll) && len(*serverAllowedCNs) == 0 && len(*serverAllowedOUs) == 0 && len(*serverAllowedDNSs) == 0 && len(*serverAllowedIPs) == 0 {
		return fmt.Errorf("at least one of --allow-all, --allow-cn, --allow-ou, --allow-dns-san or --allow-ip-san is required")
	}
	if *serverAllowAll && (len(*serverAllowedCNs) > 0 || len(*serverAllowedOUs) > 0 || len(*serverAllowedDNSs) > 0 || len(*serverAllowedIPs) > 0) {
		return fmt.Errorf("--allow-all and other access control flags are mutually exclusive")
	}
	if !*serverUnsafeTarget && !validateUnixOrLocalhost(*serverForwardAddress) {
		return fmt.Errorf("--target must be unix:PATH, localhost:PORT, 127.0.0.1:PORT or [::1]:PORT (unless --unsafe-target is set)")
	}
	return nil
}

// Validate flags for client mode
func clientValidateFlags() error {
	if !*clientUnsafeListen && !validateUnixOrLocalhost(*clientListenAddress) {
		return fmt.Errorf("--listen must be unix:PATH, localhost:PORT, 127.0.0.1:PORT or [::1]:PORT (unless --unsafe-listen is set)")
	}
	return nil
}

func main() {
	initLogger()
	runtime.GOMAXPROCS(runtime.NumCPU())

	app.Version(fmt.Sprintf("rev %s built with %s", buildRevision, buildCompiler))
	app.Validate(validateFlags)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	// metrics
	if *graphiteAddr != nil {
		logger.Printf("metrics enabled; reporting metrics via TCP to %s", *graphiteAddr)
		go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *graphiteAddr)
	}
	if *metricsURL != "" {
		logger.Printf("metrics enabled; reporting metrics via POST to %s", *metricsURL)
	}
	metrics := sqmetrics.NewMetrics(*metricsURL, *metricsPrefix, metrics.DefaultRegistry)

	// wg used to gracefully exit on SIGTERM
	listeners := &sync.WaitGroup{}
	listeners.Add(1)

	// Set up file watchers (if requested)
	watcher := make(chan bool, 1)
	if *timedReload > 0 {
		go watchFiles([]string{*keystorePath, *caBundlePath}, time.Duration(*timedReload)*time.Second, watcher)
	}

	// channel to know if ghostunnel has started
	started := make(chan bool, 1)

	switch command {
	case serverCommand.FullCommand():
		if err := serverValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s", err)
			os.Exit(1)
		}
		logger.Printf("starting ghostunnel in server mode")

		dial, err := serverBackendDialer()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid target address: %s", err)
			os.Exit(1)
		}

		status := newStatusHandler(dial)
		context := &Context{watcher, listeners, status, dial, metrics}

		// Start listening
		go serverListen(started, context)

	case clientCommand.FullCommand():
		if err := clientValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s", err)
			os.Exit(1)
		}
		logger.Printf("starting ghostunnel in client mode")

		// In client mode, we handle reload using a channel. When the signal handler
		// writes to this channel, we reload the status endpoint and rebuild the tls
		// config.
		// TODO: we should consolidate this with the server mode logic and pull the
		// whole thing into a re-usable package. Keywhiz-fs has some similar logic.
		reloadClient := make(chan bool, 1)

		dial, err := clientBackendDialer(reloadClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid target address: (%s)", err)
			os.Exit(1)
		}
		status := newStatusHandler(dial)
		context := &Context{watcher, listeners, status, dial, metrics}

		// Start listening
		go clientListen(started, reloadClient, context)
	}
	up := <-started
	if !up {
		logger.Print("failed to start initial listener")
		os.Exit(1)
	}

	logger.Print("initial startup completed, waiting for connections")
	listeners.Wait()
	logger.Print("all listeners closed, shutting down")
}

// Open listening socket in server mode. Take note that we create a
// "reusable port listener", meaning we pass SO_REUSEPORT to the kernel. This
// allows us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purpose of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is expiring.
func serverListen(started chan bool, context *Context) {
	// Open raw listening socket
	network, address := decodeAddress(*serverListenAddress)
	rawListener, err := reuseport.NewReusablePortListener(network, address)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		started <- false
		return
	}

	// Wrap listening socket with TLS listener.
	tlsConfigProxy, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion)
	if err != nil {
		logger.Printf("error setting up TLS: %s", err)
		started <- false
		return
	}

	leaf := tlsConfigProxy.Certificates[0].Leaf

	var statusListener net.Listener
	if *statusAddr != nil {
		tlsConfigStatus, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion)
		if err != nil {
			logger.Printf("error setting up TLS: %s", err)
			started <- false
			return
		}
		tlsConfigStatus.ClientAuth = tls.NoClientCert

		statusListener = serveStatus(tlsConfigStatus, context)
	}

	listener := tls.NewListener(rawListener, tlsConfigProxy)
	logger.Printf("listening on %s", *serverListenAddress)
	defer listener.Close()

	handlers := &sync.WaitGroup{}
	handlers.Add(1)

	// A channel to allow signal handlers to notify our accept loop that it
	// should shut down.
	stopper := make(chan bool, 1)

	go serverAccept(listener, handlers, stopper, leaf, context.dial)
	go serverSignalHandler(listener, statusListener, stopper, context)

	started <- true
	context.status.Listening()

	logger.Printf("listening with cert serial no. %d (expiring %s)", leaf.SerialNumber, leaf.NotAfter.String())
	handlers.Wait()

	context.listeners.Done()
}

// Open listening socket in client mode.
func clientListen(started chan bool, reloadClient chan bool, context *Context) {
	// Serve /_status.
	// reloadStatus is a channel which causes /_status to reload.
	var reloadStatus chan bool
	if *statusAddr != nil {
		tlsConfigStatus, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion)
		if err != nil {
			logger.Printf("failed to load tls config")
			started <- false
			return
		}
		tlsConfigStatus.ClientAuth = tls.NoClientCert
		statusListener := serveStatus(tlsConfigStatus, context)

		reloadStatus = make(chan bool, 1)
		go func() {
			for {
				_ = <-reloadStatus
				logger.Printf("reloading /_status")
				oldListener := statusListener
				tlsConfigStatus, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion)
				if err != nil {
					logger.Printf("failed to reload tls config")
					continue
				}
				tlsConfigStatus.ClientAuth = tls.NoClientCert
				statusListener = serveStatus(tlsConfigStatus, context)
				oldListener.Close()
			}
		}()
	}

	// Setup listening socket
	network, address, _, err := parseUnixOrTCPAddress(*clientListenAddress)
	if err != nil {
		logger.Printf("error parsing client listen address: %s", err)
		started <- false
		return
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		started <- false
		return
	}

	context.status.Listening()

	// A channel to allow signal handlers to notify our accept loop that it
	// should shut down.
	stopper := make(chan bool, 1)

	go clientSignalHandler(listener, reloadClient, stopper, reloadStatus, context)
	started <- true
	clientAccept(listener, stopper, context.dial)
	context.listeners.Done()
}

// Serve /_status (if configured)
func serveStatus(tlsConfig *tls.Config, context *Context) net.Listener {
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

	listener := tls.NewListener(rawListener, tlsConfig)
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

// Get backend dialer function in server mode (connecting to a unix socket or tcp port)
func serverBackendDialer() (func() (net.Conn, error), error) {
	backendNet, backendAddr, _, err := parseUnixOrTCPAddress(*serverForwardAddress)
	if err != nil {
		return nil, err
	}
	if backendNet == "unix" {
		// ensure file exists
		_, err = os.Stat(backendAddr)
		if err != nil {
			return nil, err
		}
	}

	return func() (net.Conn, error) {
		return net.Dial(backendNet, backendAddr)
	}, nil
}

// Get backend dialer function in client mode (connecting to a tls port)
func clientBackendDialer(reloadClient chan bool) (func() (net.Conn, error), error) {
	initial, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion)
	if err != nil {
		return nil, err
	}
	network, address, host, err := parseUnixOrTCPAddress(*clientForwardAddress)
	if err != nil {
		return nil, err
	}
	initial.ServerName = host
	// We use a channel to periodically refresh the tlsConfig
	reqc := make(chan *tls.Config)
	// Getter from channel.
	getConfig := func() *tls.Config {
		config := <-reqc
		return config
	}
	go func() {
		current := initial
		for {
			select {
			case _ = <-reloadClient:
				logger.Printf("Updating client")
				if config, err := buildConfig(*keystorePath, *keystorePass, *caBundlePath, *tlsVersion); err != nil {
					logger.Printf("Error refreshing client: %s", err)
				} else {
					config.ServerName = host
					current = config
				}
			case reqc <- current: // Service request for current config
			}
		}
	}()
	return func() (net.Conn, error) {
		return tls.Dial(network, address, getConfig())
	}, nil
}
