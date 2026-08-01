package certloader

import "errors"

var (
	// ErrUnknownFormat is returned when the file format cannot be detected.
	ErrUnknownFormat = errors.New("unable to guess file format")

	// ErrNotServerCert is returned when a certificate lacks a private key
	// and therefore cannot be used for serving TLS.
	ErrNotServerCert = errors.New("certificate cannot be used as a server")

	// ErrNoCACerts is returned when no certificates could be parsed from
	// the CA bundle.
	ErrNoCACerts = errors.New("unable to read certificates from CA bundle")

	// ErrACMENotSupportedClient is returned when ACME is used in client mode.
	ErrACMENotSupportedClient = errors.New("ACME is not supported in client mode")

	// ErrACMECertUnavailable is returned when the ACME certificate is not
	// yet available.
	ErrACMECertUnavailable = errors.New("ACME certificate currently unavailable")
)
