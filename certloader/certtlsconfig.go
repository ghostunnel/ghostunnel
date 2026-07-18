package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"sync/atomic"
)

// cachedTLSConfig pairs a built *tls.Config with the trust store it was built
// from. The pair is published together via a single atomic.Pointer so a reader
// never sees a config matched with a stale pool.
//
// It lets the hot path return a shared config instead of cloning on every
// connection. A TLS config is read-only during a handshake, so one config can
// be shared across concurrent handshakes as long as it is never mutated after
// publishing. The certificate is served through a callback that reads its own
// atomic pointer, so a cert reload needs no rebuild. The trust store has no such
// callback, so its pointer is the cache key: a reload swaps in a new pool, and
// the next call sees the mismatch and rebuilds. Two callers racing a reload may
// each rebuild once, which is harmless.
type cachedTLSConfig struct {
	pool   *x509.CertPool
	config *tls.Config
}

// TLSConfigSourceFromCertificate creates a TLSConfigSource from a Certificate.
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
	if err == nil {
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
		return nil, ErrNotServerCert
	}
	return newCertTLSConfig(c.cert, base), nil
}

type certTLSConfig struct {
	cert Certificate
	base *tls.Config

	// Cached configs, keyed on the trust-store pointer. The certificate is
	// served via a callback, so only the trust store can change the built
	// config and is the only thing that invalidates the cache.
	cachedClient atomic.Pointer[cachedTLSConfig]
	cachedServer atomic.Pointer[cachedTLSConfig]
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
	pool := c.cert.GetTrustStore()
	if cached := c.cachedClient.Load(); cached != nil && cached.pool == pool {
		return cached.config
	}
	config := c.base.Clone()
	config.GetClientCertificate = c.cert.GetClientCertificate
	config.RootCAs = pool
	c.cachedClient.Store(&cachedTLSConfig{pool: pool, config: config})
	return config
}

func (c *certTLSConfig) GetServerConfig() *tls.Config {
	pool := c.cert.GetTrustStore()
	if cached := c.cachedServer.Load(); cached != nil && cached.pool == pool {
		return cached.config
	}
	config := c.base.Clone()
	config.GetCertificate = c.cert.GetCertificate
	// Under RequireAnyClientCert (SPKI pin mode) no chain verification happens,
	// so ClientCAs never authenticates anything; its only effect is the
	// certificate_authorities hint Go advertises in the handshake. In pin mode
	// that hint is actively misleading — a strict client may withhold a pinned
	// cert that doesn't chain to it — so we leave ClientCAs nil.
	if c.base.ClientAuth != tls.RequireAnyClientCert {
		config.ClientCAs = pool
	}
	c.cachedServer.Store(&cachedTLSConfig{pool: pool, config: config})
	return config
}
