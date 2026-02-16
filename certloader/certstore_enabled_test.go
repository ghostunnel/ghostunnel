//go:build darwin || windows

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestCertstoreCertificateGetCertificate(t *testing.T) {
	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test-cert"},
	}
	tlsCert := &tls.Certificate{
		Leaf: leaf,
	}
	pool := x509.NewCertPool()

	c := &certstoreCertificate{}
	atomic.StorePointer(&c.cachedCertificate, unsafe.Pointer(tlsCert))
	atomic.StorePointer(&c.cachedCertPool, unsafe.Pointer(pool))

	cert, err := c.GetCertificate(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-cert", cert.Leaf.Subject.CommonName)
}

func TestCertstoreCertificateGetClientCertificate(t *testing.T) {
	leaf := &x509.Certificate{
		Subject: pkix.Name{CommonName: "test-client-cert"},
	}
	tlsCert := &tls.Certificate{
		Leaf: leaf,
	}

	c := &certstoreCertificate{}
	atomic.StorePointer(&c.cachedCertificate, unsafe.Pointer(tlsCert))

	cert, err := c.GetClientCertificate(nil)
	assert.Nil(t, err)
	assert.NotNil(t, cert)
	assert.Equal(t, "test-client-cert", cert.Leaf.Subject.CommonName)
}

func TestCertstoreCertificateGetIdentifier(t *testing.T) {
	leaf := &x509.Certificate{
		Subject: pkix.Name{
			CommonName:   "test-identity",
			Organization: []string{"TestOrg"},
		},
	}
	tlsCert := &tls.Certificate{
		Leaf: leaf,
	}

	c := &certstoreCertificate{}
	atomic.StorePointer(&c.cachedCertificate, unsafe.Pointer(tlsCert))

	identifier := c.GetIdentifier()
	assert.Contains(t, identifier, "test-identity")
}

func TestCertstoreCertificateGetTrustStore(t *testing.T) {
	pool := x509.NewCertPool()

	c := &certstoreCertificate{}
	atomic.StorePointer(&c.cachedCertPool, unsafe.Pointer(pool))

	trustStore := c.GetTrustStore()
	assert.NotNil(t, trustStore)
}

func TestSerializeChain(t *testing.T) {
	cert1 := &x509.Certificate{
		Raw:          []byte("cert1-raw-bytes"),
		SerialNumber: big.NewInt(1),
	}
	cert2 := &x509.Certificate{
		Raw:          []byte("cert2-raw-bytes"),
		SerialNumber: big.NewInt(2),
	}

	chain := []*x509.Certificate{cert1, cert2}
	result := serializeChain(chain)

	assert.Equal(t, 2, len(result))
	assert.Equal(t, []byte("cert1-raw-bytes"), result[0])
	assert.Equal(t, []byte("cert2-raw-bytes"), result[1])
}

func TestSerializeChainEmpty(t *testing.T) {
	result := serializeChain([]*x509.Certificate{})
	assert.Equal(t, 0, len(result))
}

