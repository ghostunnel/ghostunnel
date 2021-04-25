package spiffetest

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/internal"
	"github.com/stretchr/testify/require"
)

type CA struct {
	tb     testing.TB
	parent *CA
	cert   *x509.Certificate
	key    crypto.Signer
}

func NewCA(tb testing.TB) *CA {
	cert, key := CreateCACertificate(tb, nil, nil)
	return &CA{
		tb:   tb,
		cert: cert,
		key:  key,
	}
}

func (ca *CA) CreateCA() *CA {
	cert, key := CreateCACertificate(ca.tb, ca.cert, ca.key)
	return &CA{
		tb:     ca.tb,
		parent: ca,
		cert:   cert,
		key:    key,
	}
}

func (ca *CA) CreateX509SVID(spiffeID string) ([]*x509.Certificate, crypto.Signer) {
	cert, key := CreateX509SVID(ca.tb, ca.cert, ca.key, spiffeID)
	return append([]*x509.Certificate{cert}, ca.chain(false)...), key
}

func (ca *CA) Roots() []*x509.Certificate {
	root := ca
	for root.parent != nil {
		root = root.parent
	}
	return []*x509.Certificate{root.cert}
}

func (ca *CA) RootsPool() *x509.CertPool {
	return internal.CertPoolFromCerts(ca.Roots())
}

func CreateCACertificate(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)

	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA %x", serial),
		},
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
	}
	if parent == nil {
		parent = tmpl
		parentKey = key
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateX509SVID(tb testing.TB, parent *x509.Certificate, parentKey crypto.Signer, spiffeID string) (*x509.Certificate, crypto.Signer) {
	now := time.Now()
	serial := NewSerial(tb)

	uriSAN, err := url.Parse(spiffeID)
	require.NoError(tb, err)

	key := NewEC256Key(tb)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("X509-SVID %x", serial),
		},
		NotBefore: now,
		NotAfter:  now.Add(time.Hour),
		URIs:      []*url.URL{uriSAN},
	}
	return CreateCertificate(tb, tmpl, parent, key.Public(), parentKey), key
}

func CreateCertificate(tb testing.TB, tmpl, parent *x509.Certificate, pub, priv interface{}) *x509.Certificate {
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(tb, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(tb, err)
	return cert
}

func NewSerial(tb testing.TB) *big.Int {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	require.NoError(tb, err)
	return new(big.Int).SetBytes(b)
}

func (ca *CA) chain(includeRoot bool) []*x509.Certificate {
	chain := []*x509.Certificate{}
	next := ca
	for next != nil {
		if includeRoot || next.parent != nil {
			chain = append(chain, next.cert)
		}
		next = next.parent
	}
	return chain
}
