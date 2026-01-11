//go:build !linux

package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// identity is a certificate and private key for testing.
type identity struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	Issuer      *identity
	nextSN      int64
}

// identityOption configures identity creation.
type identityOption func(*identityConfig)

type identityConfig struct {
	subject *pkix.Name
	issuer  *identity
	priv    crypto.Signer
	isCA    bool
}

// withIsCA marks the identity as a certificate authority.
var withIsCA identityOption = func(c *identityConfig) {
	c.isCA = true
}

// withSubject sets the certificate subject.
func withSubject(name pkix.Name) identityOption {
	return func(c *identityConfig) {
		c.subject = &name
	}
}

// withPrivateKey sets a custom private key.
func withPrivateKey(key crypto.Signer) identityOption {
	return func(c *identityConfig) {
		c.priv = key
	}
}

// withIssuer sets the issuing identity.
func withIssuer(issuer *identity) identityOption {
	return func(c *identityConfig) {
		c.issuer = issuer
	}
}

// newIdentity creates a new identity (root CA or issued certificate).
func newIdentity(opts ...identityOption) *identity {
	cfg := &identityConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	// Generate private key if not provided
	priv := cfg.priv
	if priv == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		priv = key
	}

	// Build certificate template
	subject := pkix.Name{CommonName: "test"}
	if cfg.subject != nil {
		subject = *cfg.subject
	}

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               subject,
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  cfg.isCA,
		BasicConstraintsValid: true,
	}

	if cfg.isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	// Determine parent cert and signing key
	var parent *x509.Certificate
	var signingKey crypto.Signer
	var issuer *identity

	if cfg.issuer != nil {
		parent = cfg.issuer.Certificate
		signingKey = cfg.issuer.PrivateKey
		issuer = cfg.issuer
		tmpl.SerialNumber = big.NewInt(cfg.issuer.incrementSN())
	} else {
		parent = tmpl
		signingKey = priv
	}

	// Create certificate
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, priv.Public(), signingKey)
	if err != nil {
		panic(err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return &identity{
		Certificate: cert,
		PrivateKey:  priv,
		Issuer:      issuer,
		nextSN:      1,
	}
}

// Issue creates a new identity signed by this one.
func (id *identity) Issue(opts ...identityOption) *identity {
	opts = append(opts, withIssuer(id))
	return newIdentity(opts...)
}

// PFX returns the identity as PKCS#12 data encrypted with password.
func (id *identity) PFX(password string) []byte {
	pfxData, err := pkcs12.Legacy.Encode(id.PrivateKey, id.Certificate, nil, password)
	if err != nil {
		panic(err)
	}
	return pfxData
}

func (id *identity) incrementSN() int64 {
	sn := id.nextSN
	id.nextSN++
	return sn
}
