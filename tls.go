package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

// parseCertificates parses a PEM file containing multiple certificates,
// and returns them as an array of DER-encoded byte arrays.
func parseCertificates(data []byte) (leaf *x509.Certificate, certs [][]byte, err error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return
		}

		if leaf == nil {
			leaf = cert
		}

		certs = append(certs, block.Bytes)
	}

	return
}

// parsePrivateKey parses a PEM file containing a private key, and returns
// it as a crypto.PrivateKey object.
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

// buildConfig reads command-line options and builds a tls.Config
func buildConfig() *tls.Config {
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

	leaf, certChain, err := parseCertificates(certChainBytes)
	panicOnError(err)

	certAndKey := []tls.Certificate{
		tls.Certificate{
			Certificate: certChain,
			PrivateKey:  privateKey,
			Leaf:        leaf,
		},
	}

	return &tls.Config{
		// Certificates
		Certificates: certAndKey,
		RootCAs:      caBundle,
		ClientCAs:    caBundle,

		// Options
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
}
