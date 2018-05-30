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
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/cyberdelia/go-metrics-graphite"
	"github.com/hashicorp/go-syslog"
	"github.com/kavu/go_reuseport"
	"github.com/mwitkow/go-http-dialer"
	"github.com/rcrowley/go-metrics"
	"github.com/square/ghostunnel/auth"
	"github.com/square/go-sq-metrics"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	version              = "master"
	defaultMetricsPrefix = "ghostunnel"
)

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
	serverAllowedURIs    = serverCommand.Flag("allow-uri-san", "Allow clients with given URI subject alternative name (can be repeated).").PlaceHolder("SAN").Strings()
	serverDisableAuth    = serverCommand.Flag("disable-authentication", "Disable client authentication, no client certificate will be required.").Default("false").Bool()

	clientCommand       = app.Command("client", "Client mode (plain TCP/UNIX listener -> TLS target).")
	clientListenAddress = clientCommand.Flag("listen", "Address and port to listen on (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	// Note: can't use .TCP() for clientForwardAddress because we need to set the original string in tls.Config.ServerName.
	clientForwardAddress = clientCommand.Flag("target", "Address to forward connections to (HOST:PORT).").PlaceHolder("ADDR").Required().String()
	clientUnsafeListen   = clientCommand.Flag("unsafe-listen", "If set, does not limit listen to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	clientServerName     = clientCommand.Flag("override-server-name", "If set, overrides the server name used for hostname verification.").PlaceHolder("NAME").String()
	clientConnectProxy   = clientCommand.Flag("connect-proxy", "If set, connect to target over given HTTP CONNECT proxy. Must be HTTP/HTTPS URL.").PlaceHolder("URL").URL()
	clientAllowedCNs     = clientCommand.Flag("verify-cn", "Allow servers with given common name (can be repeated).").PlaceHolder("CN").Strings()
	clientAllowedOUs     = clientCommand.Flag("verify-ou", "Allow servers with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	clientAllowedDNSs    = clientCommand.Flag("verify-dns-san", "Allow servers with given DNS subject alternative name (can be repeated).").PlaceHolder("SAN").Strings()
	clientAllowedIPs     = clientCommand.Flag("verify-ip-san", "Allow servers with given IP subject alternative name (can be repeated).").PlaceHolder("SAN").IPList()
	clientAllowedURIs    = clientCommand.Flag("verify-uri-san", "Allow servers with given URI subject alternative name (can be repeated).").PlaceHolder("SAN").Strings()
	clientDisableAuth    = clientCommand.Flag("disable-authentication", "Disable client authentication, no certificate will be provided to the server.").Default("false").Bool()

	// TLS options
	keystorePath        = app.Flag("keystore", "Path to certificate and keystore (PEM with certificate/key, or PKCS12).").PlaceHolder("PATH").String()
	keystorePass        = app.Flag("storepass", "Password for certificate and keystore (optional).").PlaceHolder("PASS").String()
	caBundlePath        = app.Flag("cacert", "Path to CA bundle file (PEM/X509). Uses system trust store by default.").String()
	enabledCipherSuites = app.Flag("cipher-suites", "Set of cipher suites to enable, comma-separated, in order of preference (AES, CHACHA).").Default("AES,CHACHA").String()

	// Reloading and timeouts
	timedReload     = app.Flag("timed-reload", "Reload keystores every given interval (e.g. 300s), refresh listener/client on changes.").PlaceHolder("DURATION").Duration()
	shutdownTimeout = app.Flag("shutdown-timeout", "Graceful shutdown timeout. Terminates after timeout even if connections still open.").Default("5m").Duration()
	timeoutDuration = app.Flag("connect-timeout", "Timeout for establishing connections, handshakes.").Default("10s").Duration()

	// Metrics options
	metricsGraphite = app.Flag("metrics-graphite", "Collect metrics and report them to the given graphite instance (raw TCP).").PlaceHolder("ADDR").TCP()
	metricsURL      = app.Flag("metrics-url", "Collect metrics and POST them periodically to the given URL (via HTTP/JSON).").PlaceHolder("URL").String()
	metricsPrefix   = app.Flag("metrics-prefix", fmt.Sprintf("Set prefix string for all reported metrics (default: %s).", defaultMetricsPrefix)).PlaceHolder("PREFIX").Default(defaultMetricsPrefix).String()
	metricsInterval = app.Flag("metrics-interval", "Collect (and post/send) metrics every specified interval.").Default("30s").Duration()

	// Status & logging
	statusAddress = app.Flag("status", "Enable serving /_status and /_metrics on given HOST:PORT (or unix:SOCKET).").PlaceHolder("ADDR").String()
	enableProf    = app.Flag("enable-pprof", "Enable serving /debug/pprof endpoints alongside /_status (for profiling).").Bool()
)

var exitFunc = os.Exit

// Context groups listening context data together
type Context struct {
	watcher         chan bool
	status          *statusHandler
	statusHTTP      *http.Server
	shutdownTimeout time.Duration
	dial            func() (net.Conn, error)
	metrics         *sqmetrics.SquareMetrics
	cert            *certificate
}

// Dialer is an interface for dialers (either net.Dialer, or http_dialer.HttpTunnel)
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// Global logger instance
var logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)

func initLogger(syslog bool) (err error) {
	// If user has indicated request for syslog, override default stderr
	// logger with a syslog one instead. This can fail, e.g. in containers
	// that don't have syslog available.
	if syslog {
		var syslogWriter gsyslog.Syslogger
		syslogWriter, err = gsyslog.NewLogger(gsyslog.LOG_INFO, "DAEMON", "")
		if err == nil {
			logger = log.New(syslogWriter, "", log.LstdFlags|log.Lmicroseconds)
		}
	}
	return
}

// panicOnError panics if err is not nil
func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// Validate flags for both, server and client mode
func validateFlags(app *kingpin.Application) error {
	if *enableProf && *statusAddress == "" {
		return fmt.Errorf("--enable-pprof requires --status to be set")
	}
	if *metricsURL != "" && !strings.HasPrefix(*metricsURL, "http://") && !strings.HasPrefix(*metricsURL, "https://") {
		return fmt.Errorf("--metrics-url should start with http:// or https://")
	}
	if *timeoutDuration == 0 {
		return fmt.Errorf("--connect-timeout duration must not be zero")
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
	// hasAccessFlags is true if access control flags (besides allow-all) were specified
	hasAccessFlags := len(*serverAllowedCNs) > 0 ||
		len(*serverAllowedOUs) > 0 ||
		len(*serverAllowedDNSs) > 0 ||
		len(*serverAllowedIPs) > 0 ||
		len(*serverAllowedURIs) > 0

	if *keystorePath == "" {
		return fmt.Errorf("--keystore flag is required in server mode, try --help")
	}
	if !(*serverDisableAuth) && !(*serverAllowAll) && !hasAccessFlags {
		return fmt.Errorf("at least one access control flag (--allow-{all,cn,ou,dns-san,ip-san,uri-san} or --disable-authentication) is required")
	}
	if !(*serverDisableAuth) && *serverAllowAll && hasAccessFlags {
		return fmt.Errorf("--allow-all is mutually exclusive with other access control flags")
	}
	if *serverDisableAuth && (*serverAllowAll || hasAccessFlags) {
		return fmt.Errorf("--disable-authentication is mutually exclusive with other access control flags")
	}
	if !*serverUnsafeTarget && !validateUnixOrLocalhost(*serverForwardAddress) {
		return fmt.Errorf("--target must be unix:PATH, localhost:PORT, 127.0.0.1:PORT or [::1]:PORT (unless --unsafe-target is set)")
	}

	for _, suite := range strings.Split(*enabledCipherSuites, ",") {
		_, ok := cipherSuites[strings.TrimSpace(suite)]
		if !ok {
			return fmt.Errorf("invalid cipher suite option: %s", suite)
		}
	}
	return nil
}

// Validate flags for client mode
func clientValidateFlags() error {
	if (*keystorePath == "") && !(*clientDisableAuth) {
		fmt.Printf("one of --keystore or --disable-authentication is required, try --help\n")
		return fmt.Errorf("one of --keystore or --disable-authentication is required, try --help")
	}
	if !*clientUnsafeListen && !validateUnixOrLocalhost(*clientListenAddress) {
		return fmt.Errorf("--listen must be unix:PATH, localhost:PORT, 127.0.0.1:PORT or [::1]:PORT (unless --unsafe-listen is set)")
	}
	if *clientConnectProxy != nil && (*clientConnectProxy).Scheme != "http" && (*clientConnectProxy).Scheme != "https" {
		return fmt.Errorf("invalid CONNECT proxy %s, must have HTTP or HTTPS connection scheme", (*clientConnectProxy).String())
	}

	for _, suite := range strings.Split(*enabledCipherSuites, ",") {
		_, ok := cipherSuites[strings.TrimSpace(suite)]
		if !ok {
			return fmt.Errorf("invalid cipher suite option: %s", suite)
		}
	}
	return nil
}

func main() {
	err := run(os.Args[1:])
	if err != nil {
		exitFunc(1)
	}
	exitFunc(0)
}

func run(args []string) error {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app.Version(fmt.Sprintf("rev %s built with %s", version, runtime.Version()))
	app.Validate(validateFlags)
	app.UsageTemplate(kingpin.LongHelpTemplate)
	command := kingpin.MustParse(app.Parse(args))

	// Logger
	err := initLogger(useSyslog())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error initializing logger: %s\n", err)
		os.Exit(1)
	}

	logger.SetPrefix(fmt.Sprintf("[%d] ", os.Getpid()))
	logger.Printf("starting ghostunnel in %s mode", command)

	// Metrics
	if *metricsGraphite != nil {
		logger.Printf("metrics enabled; reporting metrics via TCP to %s", *metricsGraphite)
		go graphite.Graphite(metrics.DefaultRegistry, 1*time.Second, *metricsPrefix, *metricsGraphite)
	}
	if *metricsURL != "" {
		logger.Printf("metrics enabled; reporting metrics via POST to %s", *metricsURL)
	}

	// Read CA bundle for passing to metrics library
	ca, err := caBundle(*caBundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to build TLS config: %s\n", err)
		return err
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    ca,
			},
		},
	}
	metrics := sqmetrics.NewMetrics(*metricsURL, *metricsPrefix, client, *metricsInterval, metrics.DefaultRegistry, logger)

	// Set up file watchers (if requested)
	watcher := make(chan bool, 1)
	if *timedReload > 0 {
		go watchFiles([]string{*keystorePath}, *timedReload, watcher)
	}

	cert, err := buildCertificate(*keystorePath, *keystorePass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to load certificates: %s\n", err)
		return err
	}

	switch command {
	case serverCommand.FullCommand():
		if err := serverValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return err
		}

		dial, err := serverBackendDialer()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *serverForwardAddress)

		status := newStatusHandler(dial)
		context := &Context{watcher, status, nil, *shutdownTimeout, dial, metrics, cert}

		// Start listening
		err = serverListen(context)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error from server listen: %s\n", err)
		}
		return err

	case clientCommand.FullCommand():
		if err := clientValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err)
			return err
		}

		network, address, host, err := parseUnixOrTCPAddress(*clientForwardAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *clientForwardAddress)

		dial, err := clientBackendDialer(cert, network, address, host)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: unable to build dialer: %s\n", err)
			return err
		}

		status := newStatusHandler(dial)
		context := &Context{watcher, status, nil, *shutdownTimeout, dial, metrics, cert}

		// Start listening
		err = clientListen(context)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error from client listen: %s\n", err)
		}
		return err
	}

	return errors.New("unknown command")
}

// Open listening socket in server mode. Take note that we create a
// "reusable port listener", meaning we pass SO_REUSEPORT to the kernel. This
// allows us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purpose of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is expiring.
func serverListen(context *Context) error {
	config, err := buildConfig(*enabledCipherSuites, *caBundlePath)
	if err != nil {
		logger.Printf("error trying to read CA bundle: %s", err)
		return err
	}

	serverACL := auth.ACL{
		AllowAll:    *serverAllowAll,
		AllowedCNs:  *serverAllowedCNs,
		AllowedOUs:  *serverAllowedOUs,
		AllowedDNSs: *serverAllowedDNSs,
		AllowedIPs:  *serverAllowedIPs,
		AllowedURIs: *serverAllowedURIs,
		Logger:      logger,
	}

	config.GetCertificate = context.cert.getCertificate
	config.VerifyPeerCertificate = serverACL.VerifyPeerCertificateServer
	if *serverDisableAuth {
		config.ClientAuth = tls.NoClientCert
	}

	listener, err := reuseport.NewReusablePortListener("tcp", (*serverListenAddress).String())
	if err != nil {
		logger.Printf("error trying to listen: %s", err)
		return err
	}

	proxy := &proxy{
		quit:           0,
		listener:       tls.NewListener(listener, config),
		handlers:       &sync.WaitGroup{},
		connectTimeout: *timeoutDuration,
		dial:           context.dial,
	}

	if *statusAddress != "" {
		err := context.serveStatus()
		if err != nil {
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", (*serverListenAddress).String())

	go proxy.accept()

	context.status.Listening()
	context.signalHandler(proxy, []io.Closer{listener})
	proxy.handlers.Wait()

	return nil
}

// Open listening socket in client mode.
func clientListen(context *Context) error {
	// Setup listening socket
	network, address, _, err := parseUnixOrTCPAddress(*clientListenAddress)
	if err != nil {
		logger.Printf("error parsing client listen address: %s", err)
		return err
	}

	listener, err := net.Listen(network, address)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		return err
	}

	// If this is a UNIX socket, make sure we cleanup files on close.
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	proxy := &proxy{
		quit:           0,
		listener:       listener,
		handlers:       &sync.WaitGroup{},
		connectTimeout: *timeoutDuration,
		dial:           context.dial,
	}

	if *statusAddress != "" {
		err := context.serveStatus()
		if err != nil {
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *clientListenAddress)

	go proxy.accept()

	context.status.Listening()
	context.signalHandler(proxy, []io.Closer{listener})
	proxy.handlers.Wait()

	return nil
}

// Serve /_status (if configured)
func (context *Context) serveStatus() error {
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

	config, err := buildConfig(*enabledCipherSuites, *caBundlePath)
	if err != nil {
		return err
	}
	config.ClientAuth = tls.NoClientCert
	config.GetCertificate = context.cert.getCertificate

	network, address, _, err := parseUnixOrTCPAddress(*statusAddress)
	if err != nil {
		return err
	}

	var listener net.Listener
	if network == unixSocket {
		listener, err = net.Listen(network, address)
		listener.(*net.UnixListener).SetUnlinkOnClose(true)
	} else {
		listener, err = reuseport.NewReusablePortListener(network, address)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: unable to bind on status port: %s\n", err)
		return err
	}

	if network != unixSocket {
		listener = tls.NewListener(listener, config)
	}

	context.statusHTTP = &http.Server{
		Handler:  mux,
		ErrorLog: logger,
	}

	go func() {
		err := context.statusHTTP.Serve(listener)
		if err != nil {
			logger.Printf("error serving status port: %s", err)
		}
	}()

	return nil
}

// Get backend dialer function in server mode (connecting to a unix socket or tcp port)
func serverBackendDialer() (func() (net.Conn, error), error) {
	backendNet, backendAddr, _, err := parseUnixOrTCPAddress(*serverForwardAddress)
	if err != nil {
		return nil, err
	}

	return func() (net.Conn, error) {
		return net.DialTimeout(backendNet, backendAddr, *timeoutDuration)
	}, nil
}

// Get backend dialer function in client mode (connecting to a TLS port)
func clientBackendDialer(cert *certificate, network, address, host string) (func() (net.Conn, error), error) {
	config, err := buildConfig(*enabledCipherSuites, *caBundlePath)
	if err != nil {
		return nil, err
	}

	if *clientServerName == "" {
		config.ServerName = host
	} else {
		config.ServerName = *clientServerName
	}

	clientACL := auth.ACL{
		AllowedCNs:  *clientAllowedCNs,
		AllowedOUs:  *clientAllowedOUs,
		AllowedDNSs: *clientAllowedDNSs,
		AllowedIPs:  *clientAllowedIPs,
		AllowedURIs: *clientAllowedURIs,
		Logger:      logger,
	}

	config.VerifyPeerCertificate = clientACL.VerifyPeerCertificateClient

	var dialer Dialer = &net.Dialer{Timeout: *timeoutDuration}

	if *clientConnectProxy != nil {
		logger.Printf("using HTTP(S) CONNECT proxy %s", (*clientConnectProxy).String())

		// Use HTTP CONNECT proxy to connect to target.
		proxyConfig, err := buildConfig(*enabledCipherSuites, *caBundlePath)
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.NoClientCert

		dialer = http_dialer.New(
			*clientConnectProxy,
			http_dialer.WithDialer(dialer.(*net.Dialer)),
			http_dialer.WithTls(proxyConfig))
	}

	return func() (net.Conn, error) {
		if !(*clientDisableAuth) {
			// Fetch latest cached certificate before initiating new connection
			crt, _ := cert.getCertificate(nil)
			config.Certificates = []tls.Certificate{*crt}
		}
		return dialWithDialer(dialer, *timeoutDuration, network, address, config)
	}, nil
}
