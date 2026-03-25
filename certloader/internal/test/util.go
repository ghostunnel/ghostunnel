package spiffetest

import (
	"crypto/x509"
)

// NewCertPool returns a new CertPool with the given X.509 certificates
func NewCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func ConcatRawCertsFromCerts(certs []*x509.Certificate) []byte {
	var rawCerts []byte
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw...)
	}
	return rawCerts
}
