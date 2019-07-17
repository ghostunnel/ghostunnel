package certloader

import (
	"crypto/tls"
	"errors"
)

func TLSConfigSourceFromCertificate(cert Certificate) TLSConfigSource {
	return &certTLSConfigSource{
		cert: cert,
	}
}

type certTLSConfigSource struct {
	cert Certificate
}

func (c *certTLSConfigSource) Reload() error {
	return c.cert.Reload()
}

func (c *certTLSConfigSource) CanServe() bool {
	cert, _ := c.cert.GetCertificate(nil)
	return cert != nil
}

func (c *certTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return newCertTLSConfig(c.cert, base), nil
}

func (c *certTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	if !c.CanServe() {
		return nil, errors.New("certificate cannot be used as a server")
	}
	return newCertTLSConfig(c.cert, base), nil
}

type certTLSConfig struct {
	cert Certificate
	base *tls.Config
}

func newCertTLSConfig(cert Certificate, base *tls.Config) *certTLSConfig {
	if base == nil {
		base = new(tls.Config)
	}
	return &certTLSConfig{
		cert: cert,
		base: base,
	}
}

func (c *certTLSConfig) GetClientConfig() *tls.Config {
	config := c.base.Clone()
	config.GetClientCertificate = c.cert.GetClientCertificate
	config.RootCAs = c.cert.GetTrustStore()
	return config
}

func (c *certTLSConfig) GetServerConfig() *tls.Config {
	config := c.base.Clone()
	config.GetCertificate = c.cert.GetCertificate
	config.ClientCAs = c.cert.GetTrustStore()
	return config
}
