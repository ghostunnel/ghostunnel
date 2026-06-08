package certloader

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"sync/atomic"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

const defaultMaxAttempts = 5

// ACMEConfig stores the properties used for operating as an ACME client
type ACMEConfig struct {
	// Must be explicitly set to true by the user to indicate
	// agreement with the ACME CA's Terms of Service.
	TOSAgreed bool

	// The fully-qualified domain name being requested in the certificate.
	FQDN string

	// The email address to be associated with the ACME account used
	// to obtain a certificate from the ACME CA. This email address
	// may receive certificate lifecycle notifications from the ACME CA.
	Email string

	// The URL for the Production ACME CA to use. Defaults to the
	// Let's Encrypt production URL if not specified.
	ProdCAURL string

	// The URL for the Test/Staging ACME CA to use. Defaults to the
	// Let's Encrypt staging URL if not specified.
	TestCAURL string

	// If true, use the Test/Staging ACME CA URL. If false, use the
	// Production ACME CA URL. Defaults to false.
	UseTestCA bool

	// Path to a CA bundle file for verifying client certificates (mTLS).
	// If empty, the system certificate pool is used.
	CABundlePath string

	// Maximum number of attempts to obtain the initial ACME certificate.
	// Defaults to 5 if zero.
	MaxAttempts int

	// Override certmagic's background renewal-check interval. Zero means use
	// certmagic's default (10 minutes). Intended for the integration test
	// that needs to observe a renewal moment within a few seconds; not
	// useful as a production tuning knob.
	RenewCheckInterval time.Duration
}

// TLSConfigSourceFromACME creates a TLSConfigSource that obtains certificates via ACME.
func TLSConfigSourceFromACME(acme *ACMEConfig) (TLSConfigSource, error) {
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.Agreed = acme.TOSAgreed
	certmagic.DefaultACME.Email = acme.Email

	// certmagic uses its ACMEManager.CA value as the CA to use for obtaining
	// certs. If the desired goal is for ghostunnel to use the ACME CAs test
	// environment, we need to set certmagic's CA value to the test URL.
	//
	// certmagic uses its ACMEManager.TestCA value as an internal fallback.
	// If it encounters certain specific problems while using the CA specified
	// in the ACMEManager.CA value, it will internally (re)try against the
	// ACMEManager.TestCA value in order to test certain failure modes without
	// (potentially repeatedly) communicating with the production CA.
	//
	// Therefore, if the Ghostunnel user specifies a Test URL, we set both CA
	// and TestCA to that value. If the user does not specify a Test URL, our
	// default is to use the Let's Encrypt Test/Staging URL.
	if acme.TestCAURL != "" {
		acme.UseTestCA = true
		certmagic.DefaultACME.CA = acme.TestCAURL
		certmagic.DefaultACME.TestCA = acme.TestCAURL
	} else {
		certmagic.DefaultACME.TestCA = certmagic.LetsEncryptStagingCA
	}

	if !acme.UseTestCA {
		if acme.ProdCAURL != "" {
			certmagic.DefaultACME.CA = acme.ProdCAURL
		} else {
			certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
		}
	}

	magicConfig := newCertmagicConfig(acme.RenewCheckInterval)

	// Force an initial synchronous load of the certificate on startup,
	// but retry with backoff instead of exiting the whole process. If no certificate
	// yet exists, certmagic will attempt to obtain one from the ACME provider. If a valid
	// cert has already been obtained, it will be loaded from local cache.
	backoff := 5 * time.Second
	maxBackoff := 2 * time.Minute
	maxAttempts := acme.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = defaultMaxAttempts
	}

	var err error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = magicConfig.ManageSync(context.Background(), []string{acme.FQDN})
		if err == nil {
			break
		}

		if attempt < maxAttempts {
			log.Printf(
				"ACME initial certificate load failed (attempt %d/%d): %v; retrying in %s",
				attempt, maxAttempts, err, backoff,
			)

			time.Sleep(backoff)

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}

	if err != nil {
		return nil, err
	}

	return newACMETLSConfigSource(magicConfig, acme)
}

// newCertmagicConfig builds a certmagic.Config. If renewCheckInterval > 0,
// it creates a fresh Cache with that interval; otherwise it uses
// certmagic.NewDefault() and the package singleton cache (production path).
func newCertmagicConfig(renewCheckInterval time.Duration) *certmagic.Config {
	if renewCheckInterval <= 0 {
		return certmagic.NewDefault()
	}
	var cache *certmagic.Cache
	cache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) {
			return certmagic.New(cache, certmagic.Default), nil
		},
		RenewCheckInterval: renewCheckInterval,
		Logger:             certmagic.Default.Logger,
	})
	return certmagic.New(cache, certmagic.Default)
}

func newACMETLSConfigSource(magicConfig *certmagic.Config, acme *ACMEConfig) (*acmeTLSConfigSource, error) {
	trustStore, err := LoadTrustStore(acme.CABundlePath)
	if err != nil {
		return nil, err
	}

	source := &acmeTLSConfigSource{
		magicConfig:  magicConfig,
		gtACMEConfig: acme,
		caBundlePath: acme.CABundlePath,
	}
	source.cachedTrustStore.Store(trustStore)

	return source, nil
}

type acmeTLSConfigSource struct {
	magicConfig  *certmagic.Config
	gtACMEConfig *ACMEConfig
	caBundlePath string
	// Cached *x509.CertPool
	cachedTrustStore atomic.Pointer[x509.CertPool]
}

func (a *acmeTLSConfigSource) Reload() error {
	// certmagic automatically keeps certs updated, but we need to
	// reload the trust store (CA bundle) from disk.
	bundle, err := LoadTrustStore(a.caBundlePath)
	if err != nil {
		return err
	}

	a.cachedTrustStore.Store(bundle)
	return nil
}

func (a *acmeTLSConfigSource) getTrustStore() *x509.CertPool {
	return a.cachedTrustStore.Load()
}

func (a *acmeTLSConfigSource) CanServe() bool {
	// It does not appear that certmagic currently provides any API for determining
	// if it has a valid cert/key/chain for serving TLS connections. For now, we
	// assume certmagic correctly does its thing.
	return true
}

func (a *acmeTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	// If we assume that a significant portion of ghostunnel clients have no interface
	// exposed to the internet on tcp/443, then ACME is not suitable for obtaining client certs.
	// It should not be possible for ghostunnel to attempt to use this TLSConfigSource when
	// started in client mode.
	return nil, ErrACMENotSupportedClient
}

func (a *acmeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	if !a.CanServe() {
		return nil, ErrACMECertUnavailable
	}
	if base == nil {
		base = new(tls.Config)
	}
	return &acmeTLSConfig{
		magicConfig: a.magicConfig,
		base:        base,
		source:      a,
	}, nil
}

type acmeTLSConfig struct {
	magicConfig *certmagic.Config
	base        *tls.Config
	source      *acmeTLSConfigSource
}

func (a *acmeTLSConfig) GetServerConfig() *tls.Config {
	config := a.base.Clone()
	config.GetCertificate = a.magicConfig.GetCertificate
	config.ClientCAs = a.source.getTrustStore()
	config.NextProtos = append(config.NextProtos, acmez.ACMETLS1Protocol)

	// The ACME CA's TLS-ALPN-01 validator opens a probe handshake with
	// SupportedProtos=["acme-tls/1"] (per RFC 8737) and no client certificate.
	// If the base config requires a client cert (ghostunnel's mTLS default),
	// that probe fails and renewal silently breaks. Relax ClientAuth for that
	// exact ALPN only — every real client still gets the base mTLS enforcement.
	//
	// Tightening to prevent mTLS bypass — mirror certmagic's own gate at
	// vendor/github.com/caddyserver/certmagic/handshake.go: relax only when
	// the ClientHello matches the shape RFC 8737 mandates for a validator.
	//   - SNI is set. RFC 8737 §3 requires the validator to send the SNI of
	//     the domain being validated, and certmagic refuses to serve the
	//     challenge cert without it.
	//   - SupportedProtos is *exactly* ["acme-tls/1"]. A client sending
	//     ["acme-tls/1", "h2"] is not a validator and must not relax.
	//   - Force NextProtos=["acme-tls/1"] in the relaxed config so ALPN
	//     cannot negotiate to a different protocol on the relaxed handshake.
	//   - Disable session tickets so a ticket issued during a probe cannot
	//     be resumed by a real client to skip mTLS. (tls.Config has no
	//     server-side session cache field; SessionTicketsDisabled is the
	//     full server-side disable.)
	config.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if chi.ServerName == "" ||
			len(chi.SupportedProtos) != 1 ||
			chi.SupportedProtos[0] != acmez.ACMETLS1Protocol {
			return nil, nil
		}
		c := config.Clone()
		c.ClientAuth = tls.NoClientCert
		c.ClientCAs = nil
		c.NextProtos = []string{acmez.ACMETLS1Protocol}
		c.SessionTicketsDisabled = true
		return c, nil
	}

	return config
}
