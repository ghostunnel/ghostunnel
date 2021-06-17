package certloader

import (
	"crypto/tls"
	"errors"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
)

func TLSConfigSourceFromACME(domain, email string, useTestCA bool) (TLSConfigSource, error) {
	certmagic.DefaultACME.Agreed = true
	certmagic.DefaultACME.DisableHTTPChallenge = true
	certmagic.DefaultACME.Email = email

	if useTestCA == true {
		certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	}

	magicConfig := certmagic.NewDefault()

	// Force an iniial synchronous load of the certificate on startup. If no certificate
	// yet exists, certmagic will attempt to obtain one from the ACME provider. If a valid
	// cert has already been obtained, it will be loaded from local cache.
	err := magicConfig.ManageSync([]string{domain})
	if err != nil {
		return nil, err
	}

	return &acmeTLSConfigSource{
		magicConfig: magicConfig,
		domain:      domain,
		email:       email,
	}, nil
}

type acmeTLSConfigSource struct {
	magicConfig *certmagic.Config
	domain      string
	email       string
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
	config.NextProtos = append(config.NextProtos, acmez.ACMETLS1Protocol)
	return config
}
