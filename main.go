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
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime"
	"strings"
	"time"

	graphite "github.com/cyberdelia/go-metrics-graphite"
	gsyslog "github.com/hashicorp/go-syslog"
	http_dialer "github.com/mwitkow/go-http-dialer"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	metrics "github.com/rcrowley/go-metrics"
	"github.com/square/ghostunnel/auth"
	"github.com/square/ghostunnel/certloader"
	"github.com/square/ghostunnel/proxy"
	"github.com/square/ghostunnel/socket"
	"github.com/square/ghostunnel/wildcard"
	sqmetrics "github.com/square/go-sq-metrics"
	kingpin "gopkg.in/alecthomas/kingpin.v2"

	prometheusmetrics "github.com/deathowl/go-metrics-prometheus"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	version              = "master"
	defaultMetricsPrefix = "ghostunnel"
)

// Optional flags (enabled conditionally based on build)
var (
	keychainIdentity *string
	pkcs11Module     *string
	pkcs11TokenLabel *string
	pkcs11PIN        *string
)

// Main flags (always supported)
var (
	app = kingpin.New("ghostunnel", "A simple SSL/TLS proxy with mutual authentication for securing non-TLS services.")

	serverCommand        = app.Command("server", "Server mode (TLS listener -> plain TCP/UNIX target).")
	serverListenAddress  = serverCommand.Flag("listen", "Address and port to listen on (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	serverForwardAddress = serverCommand.Flag("target", "Address to forward connections to (HOST:PORT, or unix:PATH).").PlaceHolder("ADDR").Required().String()
	serverProxyProtocol  = serverCommand.Flag("proxy-protocol", "Enable PROXY protocol v2 to signal connection info to backend").Bool()
	serverUnsafeTarget   = serverCommand.Flag("unsafe-target", "If set, does not limit target to localhost, 127.0.0.1, [::1], or UNIX sockets.").Bool()
	serverAllowAll       = serverCommand.Flag("allow-all", "Allow all clients, do not check client cert subject.").Bool()
	serverAllowedCNs     = serverCommand.Flag("allow-cn", "Allow clients with given common name (can be repeated).").PlaceHolder("CN").Strings()
	serverAllowedOUs     = serverCommand.Flag("allow-ou", "Allow clients with given organizational unit name (can be repeated).").PlaceHolder("OU").Strings()
	serverAllowedDNSs    = serverCommand.Flag("allow-dns", "Allow clients with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	serverAllowedIPs     = serverCommand.Flag("allow-ip", "").Hidden().PlaceHolder("SAN").IPList()
	serverAllowedURIs    = serverCommand.Flag("allow-uri", "Allow clients with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
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
	clientAllowedDNSs    = clientCommand.Flag("verify-dns", "Allow servers with given DNS subject alternative name (can be repeated).").PlaceHolder("DNS").Strings()
	clientAllowedIPs     = clientCommand.Flag("verify-ip", "").Hidden().PlaceHolder("SAN").IPList()
	clientAllowedURIs    = clientCommand.Flag("verify-uri", "Allow servers with given URI subject alternative name (can be repeated).").PlaceHolder("URI").Strings()
	clientDisableAuth    = clientCommand.Flag("disable-authentication", "Disable client authentication, no certificate will be provided to the server.").Default("false").Bool()

	// TLS options
	keystorePath        = app.Flag("keystore", "Path to keystore (combined PEM with cert/key, or PKCS12 keystore).").PlaceHolder("PATH").String()
	certPath            = app.Flag("cert", "Path to certificate (PEM with certificate chain).").PlaceHolder("PATH").String()
	keyPath             = app.Flag("key", "Path to certificate private key (PEM with private key).").PlaceHolder("PATH").String()
	keystorePass        = app.Flag("storepass", "Password for keystore (if using PKCS keystore, optional).").PlaceHolder("PASS").String()
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
	quiet         = app.Flag("quiet", "Silence log messages (can be all, conns, conn-errs, handshake-errs; repeat flag for more than one)").Default("").Enums("", "all", "conns", "handshake-errs", "conn-errs")

	// Man page /help
	helpMan = app.Flag("help-custom-man", "Generate a man page.").Hidden().PreAction(generateManPage).Bool()
)

func init() {
	// Optional keychain identity flag, if compiled for a supported platform
	if certloader.SupportsKeychain() {
		keychainIdentity = app.Flag("keychain-identity", "Use local keychain identity with given common name (instead of keystore file).").PlaceHolder("CN").String()
	}

	// Optional PKCS#11 flags, if compiled with CGO enabled
	if certloader.SupportsPKCS11() {
		pkcs11Module = app.Flag("pkcs11-module", "Path to PKCS11 module (SO) file (optional).").Envar("PKCS11_MODULE").PlaceHolder("PATH").ExistingFile()
		pkcs11TokenLabel = app.Flag("pkcs11-token-label", "Token label for slot/key in PKCS11 module (optional).").Envar("PKCS11_TOKEN_LABEL").PlaceHolder("LABEL").String()
		pkcs11PIN = app.Flag("pkcs11-pin", "PIN code for slot/key in PKCS11 module (optional).").Envar("PKCS11_PIN").PlaceHolder("PIN").String()
	}

	// Aliases for flags that were renamed to be backwards-compatible
	serverCommand.Flag("allow-dns-san", "").Hidden().StringsVar(serverAllowedDNSs)
	serverCommand.Flag("allow-ip-san", "").Hidden().IPListVar(serverAllowedIPs)
	serverCommand.Flag("allow-uri-san", "").Hidden().StringsVar(serverAllowedURIs)
	clientCommand.Flag("verify-dns-san", "").Hidden().StringsVar(clientAllowedDNSs)
	clientCommand.Flag("verify-ip-san", "").Hidden().IPListVar(clientAllowedIPs)
	clientCommand.Flag("verify-uri-san", "").Hidden().StringsVar(clientAllowedURIs)
}

var exitFunc = os.Exit

// Context groups listening context data together
type Context struct {
	status          *statusHandler
	statusHTTP      *http.Server
	shutdownTimeout time.Duration
	dial            func() (net.Conn, error)
	metrics         *sqmetrics.SquareMetrics
	cert            certloader.Certificate
}

// Dialer is an interface for dialers (either net.Dialer, or http_dialer.HttpTunnel)
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// Global logger instance
var logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)

func initLogger(syslog bool, flags []string) (err error) {
	// If user has indicated request for syslog, override default stderr
	// logger with a syslog one instead. This can fail, e.g. in containers
	// that don't have syslog available.
	for _, flag := range flags {
		if flag == "all" {
			// If --quiet=all if passed, disable all logging
			logger = log.New(ioutil.Discard, "", 0)
			return
		}
	}
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

// Validates that addr is "safe" and does not need --unsafe-listen (or --unsafe-target).
func consideredSafe(addr string) bool {
	safePrefixes := []string{
		"unix:",
		"systemd:",
		"launchd:",
		"127.0.0.1:",
		"[::1]:",
		"localhost:",
	}
	for _, prefix := range safePrefixes {
		if strings.HasPrefix(addr, prefix) {
			return true
		}
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

	if ((*keyPath != "" && *certPath == "") || (*keyPath == "" && *certPath != "")) && !hasPKCS11() {
		return errors.New("when using --cert, must also specify --key")
	}
	if *certPath != "" && *keystorePath != "" {
		return errors.New("--key/--cert and --keystore are mutually exclusive")
	}
	if *keystorePath == "" && !hasKeychainIdentity() && *certPath == "" {
		return errors.New("at least one of --keystore, --cert/--key or --keychain-identity (if supported) flags is required")
	}
	if *keystorePath != "" && hasKeychainIdentity() {
		return errors.New("--keystore and --keychain-identity flags are mutually exclusive")
	}
	if *certPath != "" && hasKeychainIdentity() {
		return errors.New("--cert/--key and --keychain-identity flags are mutually exclusive")
	}
	if !(*serverDisableAuth) && !(*serverAllowAll) && !hasAccessFlags {
		return errors.New("at least one access control flag (--allow-{all,cn,ou,dns-san,ip-san,uri-san} or --disable-authentication) is required")
	}
	if !(*serverDisableAuth) && *serverAllowAll && hasAccessFlags {
		return errors.New("--allow-all is mutually exclusive with other access control flags")
	}
	if *serverDisableAuth && (*serverAllowAll || hasAccessFlags) {
		return errors.New("--disable-authentication is mutually exclusive with other access control flags")
	}
	if !*serverUnsafeTarget && !consideredSafe(*serverForwardAddress) {
		return errors.New("--target must be unix:PATH or localhost:PORT (unless --unsafe-target is set)")
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
	if *keystorePath == "" && !hasKeychainIdentity() && !*clientDisableAuth {
		return errors.New("at least one of --keystore, --keychain-identity (if supported), or --disable-authentication flags is required")
	}
	if (*keystorePath != "" && hasKeychainIdentity()) ||
		(*keystorePath != "" && *clientDisableAuth) ||
		(hasKeychainIdentity() && *clientDisableAuth) {
		return errors.New("--keystore, --keychain-identity, and --disable-authentication flags are mutually exclusive")
	}
	if !*clientUnsafeListen && !consideredSafe(*clientListenAddress) {
		return fmt.Errorf("--listen must be unix:PATH, localhost:PORT, systemd:NAME or launchd:NAME (unless --unsafe-listen is set)")
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
	err := initLogger(useSyslog(), *quiet)
	if err != nil {
		logger.Printf("error initializing logger: %s\n", err)
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
	// Always enable prometheus registry. The overhead should be quite minimal as an in-mem map is updated
	// with the values.
	pClient := prometheusmetrics.NewPrometheusProvider(metrics.DefaultRegistry, *metricsPrefix, "", prometheus.DefaultRegisterer, 1*time.Second)
	go pClient.UpdatePrometheusMetrics()

	// Read CA bundle for passing to metrics library
	ca, err := certloader.LoadTrustStore(*caBundlePath)
	if err != nil {
		logger.Printf("error: unable to build TLS config: %s\n", err)
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

	cert, err := buildCertificate(*keystorePath, *certPath, *keyPath, *keystorePass, *caBundlePath)
	if err != nil {
		logger.Printf("error: unable to load certificates: %s\n", err)
		return err
	}

	switch command {
	case serverCommand.FullCommand():
		if err := serverValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		dial, err := serverBackendDialer()
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *serverForwardAddress)

		status := newStatusHandler(dial)
		context := &Context{status, nil, *shutdownTimeout, dial, metrics, cert}
		go context.reloadHandler(*timedReload)

		// Start listening
		err = serverListen(context)
		if err != nil {
			logger.Printf("error from server listen: %s\n", err)
		}
		return err

	case clientCommand.FullCommand():
		if err := clientValidateFlags(); err != nil {
			logger.Printf("error: %s\n", err)
			return err
		}

		network, address, host, err := socket.ParseAddress(*clientForwardAddress)
		if err != nil {
			logger.Printf("error: invalid target address: %s\n", err)
			return err
		}
		logger.Printf("using target address %s", *clientForwardAddress)

		dial, err := clientBackendDialer(cert, network, address, host)
		if err != nil {
			logger.Printf("error: unable to build dialer: %s\n", err)
			return err
		}

		status := newStatusHandler(dial)
		context := &Context{status, nil, *shutdownTimeout, dial, metrics, cert}
		go context.reloadHandler(*timedReload)

		// Start listening
		err = clientListen(context)
		if err != nil {
			logger.Printf("error from client listen: %s\n", err)
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
	config, err := buildConfig(*enabledCipherSuites)
	if err != nil {
		logger.Printf("error trying to read CA bundle: %s", err)
		return err
	}

	allowedURIs, err := wildcard.CompileList(*serverAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --allow-uri flag (%s)", err)
		return err
	}

	serverACL := auth.ACL{
		AllowAll:    *serverAllowAll,
		AllowedCNs:  *serverAllowedCNs,
		AllowedOUs:  *serverAllowedOUs,
		AllowedDNSs: *serverAllowedDNSs,
		AllowedIPs:  *serverAllowedIPs,
		AllowedURIs: allowedURIs,
		Logger:      logger,
	}

	if *serverDisableAuth {
		config.ClientAuth = tls.NoClientCert
	} else {
		config.VerifyPeerCertificate = serverACL.VerifyPeerCertificateServer
	}

	listener, err := socket.ParseAndOpen(*serverListenAddress)
	if err != nil {
		logger.Printf("error trying to listen: %s", err)
		return err
	}

	p := proxy.New(
		certloader.NewListener(listener, context.cert, config),
		*timeoutDuration,
		context.dial,
		logger,
		proxyLoggerFlags(*quiet),
		*serverProxyProtocol,
	)

	if *statusAddress != "" {
		err := context.serveStatus()
		if err != nil {
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *serverListenAddress)

	go p.Accept()

	context.status.Listening()
	context.signalHandler(p)
	p.Wait()

	return nil
}

// Open listening socket in client mode.
func clientListen(context *Context) error {
	listener, err := socket.ParseAndOpen(*clientListenAddress)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		return err
	}

	// If this is a UNIX socket, make sure we cleanup files on close.
	if ul, ok := listener.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	p := proxy.New(
		listener,
		*timeoutDuration,
		context.dial,
		logger,
		proxyLoggerFlags(*quiet),
		false,
	)

	if *statusAddress != "" {
		err := context.serveStatus()
		if err != nil {
			logger.Printf("error serving /_status: %s", err)
			return err
		}
	}

	logger.Printf("listening for connections on %s", *clientListenAddress)

	go p.Accept()

	context.status.Listening()
	context.signalHandler(p)
	p.Wait()

	return nil
}

// Serve /_status (if configured)
func (context *Context) serveStatus() error {
	promHandler := promhttp.Handler()

	mux := http.NewServeMux()
	mux.Handle("/_status", context.status)
	mux.HandleFunc("/_metrics", func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		format, ok := params["format"]
		if !ok || format[0] != "prometheus" {
			context.metrics.ServeHTTP(w, r)
			return
		}
		promHandler.ServeHTTP(w, r)
	})

	if *enableProf {
		mux.Handle("/debug/pprof/", http.HandlerFunc(pprof.Index))
		mux.Handle("/debug/pprof/cmdline", http.HandlerFunc(pprof.Cmdline))
		mux.Handle("/debug/pprof/profile", http.HandlerFunc(pprof.Profile))
		mux.Handle("/debug/pprof/symbol", http.HandlerFunc(pprof.Symbol))
		mux.Handle("/debug/pprof/trace", http.HandlerFunc(pprof.Trace))
	}

	network, address, _, err := socket.ParseAddress(*statusAddress)
	if err != nil {
		return err
	}

	listener, err := socket.Open(network, address)
	if err != nil {
		logger.Printf("error: unable to bind on status port: %s\n", err)
		return err
	}

	cert, _ := context.cert.GetCertificate(nil)
	if network != "unix" && cert != nil {
		config, err := buildConfig(*enabledCipherSuites)
		if err != nil {
			return err
		}
		config.ClientAuth = tls.NoClientCert
		listener = certloader.NewListener(listener, context.cert, config)
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
	backendNet, backendAddr, _, err := socket.ParseAddress(*serverForwardAddress)
	if err != nil {
		return nil, err
	}

	return func() (net.Conn, error) {
		return net.DialTimeout(backendNet, backendAddr, *timeoutDuration)
	}, nil
}

// Get backend dialer function in client mode (connecting to a TLS port)
func clientBackendDialer(cert certloader.Certificate, network, address, host string) (func() (net.Conn, error), error) {
	config, err := buildConfig(*enabledCipherSuites)
	if err != nil {
		return nil, err
	}

	if *clientServerName == "" {
		config.ServerName = host
	} else {
		config.ServerName = *clientServerName
	}

	allowedURIs, err := wildcard.CompileList(*clientAllowedURIs)
	if err != nil {
		logger.Printf("invalid URI pattern in --verify-uri flag (%s)", err)
		return nil, err
	}

	clientACL := auth.ACL{
		AllowedCNs:  *clientAllowedCNs,
		AllowedOUs:  *clientAllowedOUs,
		AllowedDNSs: *clientAllowedDNSs,
		AllowedIPs:  *clientAllowedIPs,
		AllowedURIs: allowedURIs,
		Logger:      logger,
	}

	config.VerifyPeerCertificate = clientACL.VerifyPeerCertificateClient

	var dialer Dialer = &net.Dialer{Timeout: *timeoutDuration}

	if *clientConnectProxy != nil {
		logger.Printf("using HTTP(S) CONNECT proxy %s", (*clientConnectProxy).String())

		// Use HTTP CONNECT proxy to connect to target.
		proxyConfig, err := buildConfig(*enabledCipherSuites)
		if err != nil {
			return nil, err
		}
		config.ClientAuth = tls.NoClientCert

		// Read CA bundle for passing to proxy library
		ca, err := certloader.LoadTrustStore(*caBundlePath)
		if err != nil {
			logger.Printf("error: unable to build TLS config: %s\n", err)
			return nil, err
		}
		config.RootCAs = ca

		dialer = http_dialer.New(
			*clientConnectProxy,
			http_dialer.WithDialer(dialer.(*net.Dialer)),
			http_dialer.WithTls(proxyConfig))
	}

	d := certloader.DialerWithCertificate(cert, config, *timeoutDuration, dialer)
	return func() (net.Conn, error) { return d.Dial(network, address) }, nil
}

func proxyLoggerFlags(flags []string) int {
	out := proxy.LogEverything
	for _, flag := range flags {
		switch flag {
		case "all":
			// Disable all proxy logs
			out = 0
		case "conns":
			// Disable connection logs
			out = out & ^proxy.LogConnections
		case "conn-errs":
			// Disable connection errors logs
			out = out & ^proxy.LogConnectionErrors
		case "handshake-errs":
			// Disable handshake error logs
			out = out & ^proxy.LogHandshakeErrors
		}
	}
	return out
}
