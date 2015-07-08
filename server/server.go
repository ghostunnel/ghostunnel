package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
)

var listenAddress = "0.0.0.0:8043"
var privateKeyPath = "server.key"
var certChainPath = "server.crt"
var caBundlePath = "ca-bundle.crt"

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
	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
	panicOnError(err)

	caBundle := x509.NewCertPool()
	caBundle.AppendCertsFromPEM(caBundleBytes)

	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	panicOnError(err)

	privateKey, err := parsePrivateKey(privateKeyBytes)
	panicOnError(err)

	certChainBytes, err := ioutil.ReadFile(certChainPath)
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

	listener, err := tls.Listen("tcp", listenAddress, &config)
	panicOnError(err)

	log.Printf("Listening on %s", listenAddress)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %s", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	log.Printf("New connection from %s", conn.RemoteAddr())

	defer conn.Close()
	n, err := io.Copy(os.Stdout, conn)

	if err == nil {
		log.Printf("Closed connection from %s (success, copied %d bytes total)", conn.RemoteAddr(), n)
	} else {
		log.Printf("Closed connection from %s (%s)", conn.RemoteAddr(), err)
	}
}
