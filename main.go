package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"runtime"
	"sync"

	"github.com/kavu/go_reuseport"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	// Startup flags
	listenAddress  = kingpin.Flag("listen", "Address and port to listen on").Required().TCP()
	forwardAddress = kingpin.Flag("target", "Address to foward connections to").Required().TCP()
	privateKeyPath = kingpin.Flag("key", "Path to private key file (PEM/PKCS1)").Required().String()
	certChainPath  = kingpin.Flag("cert", "Path to certificate chain file (PEM/X509)").Required().String()
	caBundlePath   = kingpin.Flag("cacert", "Path to certificate authority bundle file (PEM/X509)").Required().String()
	useSyslog      = kingpin.Flag("syslog", "Send logs to syslog instead of stderr").Bool()
	allowAll       = kingpin.Flag("allow-all", "Allow all clients, do not check client cert subject").Bool()
	allowedCNs     = kingpin.Flag("allow-cn", "Allow clients with given common name (can be repeated)").PlaceHolder("CN").Strings()
	allowedOUs     = kingpin.Flag("allow-ou", "Allow clients with organizational unit name (can be repeated)").PlaceHolder("OU").Strings()
)

// Global logger instance
var logger *log.Logger

func initLogger() {
	if *useSyslog {
		var err error
		logger, err = syslog.NewLogger(syslog.LOG_NOTICE|syslog.LOG_DAEMON, log.LstdFlags|log.Lmicroseconds)
		panicOnError(err)
	} else {
		logger = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
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

	if !(*allowAll) && len(*allowedCNs) == 0 && len(*allowedOUs) == 0 {
		fmt.Fprintf(os.Stderr, "ghosttunel: error: at least one of --allow-all, --allow-cn or --allow-ou is required")
		os.Exit(1)
	}

	initLogger()

	listeners := &sync.WaitGroup{}
	listeners.Add(1)

	// A channel to notify us that the listener is running.
	started := make(chan bool, 1)
	go listen(started, listeners)

	up := <-started
	if !up {
		logger.Printf("failed to start initial listener")
		os.Exit(1)
	}

	logger.Printf("initial startup completed, waiting for connections")
	listeners.Wait()
	logger.Printf("all listeners closed, shutting down")
}

// Open listening socket. Take note that we create a "reusable port
// listener", meaning we pass SO_REUSEPORT to the kernel. This allows
// us to have multiple sockets listening on the same port and accept
// connections. This is useful for the purposes of replacing certificates
// in-place without having to take downtime, e.g. if a certificate is
// expiring.
func listen(started chan bool, listeners *sync.WaitGroup) {
	// Open raw listening socket
	network, address := decodeAddress(*listenAddress)
	rawListener, err := reuseport.NewReusablePortListener(network, address)
	if err != nil {
		logger.Printf("error opening socket: %s", err)
		started <- false
		return
	}

	// Wrap listening socket with TLS listener.
	tlsConfig := buildConfig()
	leaf := tlsConfig.Certificates[0].Leaf

	listener := tls.NewListener(rawListener, tlsConfig)
	logger.Printf("listening on %s", *listenAddress)
	defer listener.Close()

	handlers := &sync.WaitGroup{}
	handlers.Add(1)

	// A channel to allow signal handlers to notify our accept loop that it
	// should shut down.
	stopper := make(chan bool, 1)

	go accept(listener, handlers, stopper, leaf)
	go signalHandler(listener, stopper, listeners)

	started <- true

	logger.Printf("listening with cert serial no. %d (expiring %s)", leaf.SerialNumber, leaf.NotAfter.String())
	handlers.Wait()

	listeners.Done()
}
