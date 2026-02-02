package certloader

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/caddyserver/certmagic"
)

// acmeTLS1Protocol is the ALPN value for the ACME TLS-ALPN-01 challenge.
// See https://datatracker.ietf.org/doc/html/rfc8737#section-6.1
const acmeTLS1Protocol = "acme-tls/1"

// ACMEConfig stores the properties used for operating as an ACME client
type ACMEConfig struct {
	// Must be explicitly set to true by the user to indicate
	// agreement with the ACME CA's Terms of Service.
	TOSAgreed bool

	// The fully-qualified domain name being requested in the certificate.
	FQDN string

	// The email address to be associated with the ACME account used
	// to obtain a certificate from the ACME CA. This email address
	// may receive certificate lifecycle notificates from the ACME CA.
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
}

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

	magicConfig := certmagic.NewDefault()

	// Force an initial synchronous load of the certificate on startup. If no certificate
	// yet exists, certmagic will attempt to obtain one from the ACME provider. If a valid
	// cert has already been obtained, it will be loaded from local cache.
	err := magicConfig.ManageSync(context.Background(), []string{acme.FQDN})
	if err != nil {
		return nil, err
	}

	return &acmeTLSConfigSource{
		magicConfig:  magicConfig,
		gtACMEConfig: acme,
	}, nil
}

type acmeTLSConfigSource struct {
	magicConfig  *certmagic.Config
	gtACMEConfig *ACMEConfig
}

func (a *acmeTLSConfigSource) Reload() error {
	// certmagic automatically keeps certs updated
	return nil
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
	return nil, errors.New("ACME is not supported in client mode")
}

func (a *acmeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	if !a.CanServe() {
		return nil, errors.New("ACME certificate currently unavailable")
	}
	if base == nil {
		base = new(tls.Config)
	}
	return &acmeTLSConfig{
		magicConfig: a.magicConfig,
		base:        base,
	}, nil
}

type acmeTLSConfig struct {
	magicConfig *certmagic.Config
	base        *tls.Config
}

func (a *acmeTLSConfig) GetServerConfig() *tls.Config {
	config := a.base.Clone()
	config.GetCertificate = a.magicConfig.GetCertificate
	config.NextProtos = append(config.NextProtos, acmeTLS1Protocol)
	return config
}
