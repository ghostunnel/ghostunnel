package certloader

import (
	"crypto/tls"
	"errors"
	"log"
)

func TLSConfigSourceFromCertificate(cert Certificate, logger *log.Logger) TLSConfigSource {
	return &certTLSConfigSource{
		cert:   cert,
		logger: logger,
	}
}

type certTLSConfigSource struct {
	cert   Certificate
	logger *log.Logger
}

func (c *certTLSConfigSource) Reload() error {
	err := c.cert.Reload()
	if err != nil {
		id := c.cert.GetIdentifier()
		if id != "" {
			c.logger.Printf("loaded certificate: %s", id)
		}
	}
	return err
}

func (c *certTLSConfigSource) CanServe() bool {
	cert, _ := c.cert.GetCertificate(nil)
	return cert != nil && cert.PrivateKey != nil
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
