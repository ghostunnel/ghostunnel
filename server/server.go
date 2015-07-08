package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/kardianos/osext"
	"github.com/kavu/go_reuseport"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	listenAddress  = kingpin.Flag("addr", "Address and port to listen on").Required().TCP()
	privateKeyPath = kingpin.Flag("key", "Path to private key file (PEM/PKCS1)").Required().String()
	certChainPath  = kingpin.Flag("cert", "Path to certificate chain file (PEM/X509)").Required().String()
	caBundlePath   = kingpin.Flag("cacert", "Path to CA certificate bundle file (PEM/X509)").Required().String()
	gracefulChild  = kingpin.Flag("graceful", "Send SIGTERM to parent after startup (internal)").Bool()
)

func init() {
	log.SetPrefix(fmt.Sprintf("[%5d] ", os.Getpid()))
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func parseCertificates(data []byte) (certs [][]byte, err error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		_, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}

		certs = append(certs, block.Bytes)
	}

	return
}

func parsePrivateKey(data []byte) (key crypto.PrivateKey, err error) {
	var block *pem.Block
	block, _ = pem.Decode(data)
	if block == nil {
		err = errors.New("invalid private key pem")
		return
	}

	key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	kingpin.Parse()

	caBundleBytes, err := ioutil.ReadFile(*caBundlePath)
	panicOnError(err)

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(caBundleBytes)

	privateKeyBytes, err := ioutil.ReadFile(*privateKeyPath)
	panicOnError(err)

	privateKey, err := parsePrivateKey(privateKeyBytes)
	panicOnError(err)

	certChainBytes, err := ioutil.ReadFile(*certChainPath)
	panicOnError(err)

	certChain, err := parseCertificates(certChainBytes)
	panicOnError(err)

	certAndKey := []tls.Certificate{
		tls.Certificate{
			Certificate: certChain,
			PrivateKey:  privateKey,
		},
	}

	config := tls.Config{
		// Certificates
		Certificates: certAndKey,
		RootCAs:      caBundle,
		ClientCAs:    caBundle,

		// Options
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	var proto string
	if (*listenAddress).IP.To4() != nil {
		proto = "tcp4"
	} else {
		proto = "tcp6"
	}

	rawListener, err := reuseport.NewReusablePortListener(proto, (*listenAddress).String())
	panicOnError(err)

	listener := tls.NewListener(rawListener, &config)

	log.Printf("Listening on %s", *listenAddress)

	wg := &sync.WaitGroup{}
	wg.Add(1)

	stopper := make(chan bool, 1)

	go accept(listener, wg, stopper)
	go sigtermHandler(listener, stopper)
	go sigusr1Handler()

	if *gracefulChild {
		parent := syscall.Getppid()
		log.Printf("Sending SIGTERM to parent PID %d", parent)
		syscall.Kill(parent, syscall.SIGTERM)
	}

	log.Printf("Startup completed, waiting for connections")

	wg.Wait()

	log.Printf("All connections closed, shutting down")
}

func sigtermHandler(listener net.Listener, stopper chan bool) {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGTERM)

	<-signals
	stopper <- true

	log.Printf("Got SIGTERM, closing listening socket")
	signal.Stop(signals)
	listener.Close()
}

func sigusr1Handler() {
	signals := make(chan os.Signal)
	signal.Notify(signals, syscall.SIGUSR1)

	for {
		<-signals

		log.Printf("Received SIGUSR1, attempting restart")
		go reexec()
	}
}

func reexec() {
	path, err := osext.Executable()
	if err != nil {
		log.Printf("Failed to get executable path: %s", err)
	}

	args := []string{"--graceful"}
	for _, val := range os.Args[1:] {
		if val != "--graceful" {
			args = append(args, val)
		}
	}

	log.Printf("Executing self: %s %s", path, strings.Join(args, " "))

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()

	if err != nil {
		log.Printf("Child failed with error: %s", err)
	}
}

func accept(listener net.Listener, wg *sync.WaitGroup, stopper chan bool) {
	defer wg.Done()
	defer listener.Close()

	for {
		conn, err := listener.Accept()

		// Check if we're supposed to stop
		select {
		case _ = <-stopper:
			return
		default:
		}

		if err != nil {
			log.Printf("Error accepting connection: %s", err)
			continue
		}

		wg.Add(1)
		go handle(conn, wg)
	}

	log.Printf("Closing listening socket")
}

func handle(conn net.Conn, wg *sync.WaitGroup) {
	defer wg.Done()
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	n, err := io.Copy(os.Stdout, conn)

	if err == nil {
		log.Printf("Closed connection from %s (success, copied %d bytes total)", conn.RemoteAddr(), n)
	} else {
		log.Printf("Closed connection from %s (%s)", conn.RemoteAddr(), err)
	}
}
