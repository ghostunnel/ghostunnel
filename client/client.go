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
	"os"
)

var connectAddress = "127.0.0.1:8043"
var privateKeyPath = "client.key"
var certChainPath = "client.crt"
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
		MinVersion: tls.VersionTLS12,
	}

	log.Printf("Dialing %s\n", connectAddress)

	conn, err := tls.Dial("tcp", connectAddress, &config)
	panicOnError(err)

	log.Printf("Established connection with %s\n", conn.RemoteAddr())

	defer conn.Close()
	n, err := io.Copy(conn, os.Stdin)

	if err == nil {
		log.Printf("Closed connection with %s (success, copied %d bytes total)", conn.RemoteAddr(), n)
	} else {
		log.Printf("Closed connection with %s (%s)", conn.RemoteAddr(), err)
	}
}
