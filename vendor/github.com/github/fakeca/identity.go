package fakeca

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os/exec"
)

// Identity is a certificate and private key.
type Identity struct {
	Issuer      *Identity
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	NextSN      int64
}

// New creates a new CA.
func New(opts ...Option) *Identity {
	c := &configuration{}

	for _, opt := range opts {
		option(opt)(c)
	}

	return c.generate()
}

// Issue issues a new Identity with this one as its parent.
func (id *Identity) Issue(opts ...Option) *Identity {
	opts = append(opts, Issuer(id))
	return New(opts...)
}

// PFX wraps the certificate and private key in an encrypted PKCS#12 packet. The
// provided password must be alphanumeric.
func (id *Identity) PFX(password string) []byte {
	return toPFX(id.Certificate, id.PrivateKey, password)
}

// Chain builds a slice of *x509.Certificate from this CA and its issuers.
func (id *Identity) Chain() []*x509.Certificate {
	chain := []*x509.Certificate{}
	for this := id; this != nil; this = this.Issuer {
		chain = append(chain, this.Certificate)
	}

	return chain
}

// ChainPool builds an *x509.CertPool from this CA and its issuers.
func (id *Identity) ChainPool() *x509.CertPool {
	chain := x509.NewCertPool()
	for this := id; this != nil; this = this.Issuer {
		chain.AddCert(this.Certificate)
	}

	return chain
}

// IncrementSN returns the next serial number.
func (id *Identity) IncrementSN() int64 {
	defer func() {
		id.NextSN++
	}()

	return id.NextSN
}

func toPFX(cert *x509.Certificate, priv interface{}, password string) []byte {
	// only allow alphanumeric passwords
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		default:
			panic("password must be alphanumeric")
		}
	}

	passout := fmt.Sprintf("pass:%s", password)
	cmd := exec.Command("openssl", "pkcs12", "-export", "-passout", passout)

	cmd.Stdin = bytes.NewReader(append(append(toPKCS8(priv), '\n'), toPEM(cert)...))

	out := new(bytes.Buffer)
	cmd.Stdout = out

	if err := cmd.Run(); err != nil {
		panic(err)
	}

	return out.Bytes()
}

func toPEM(cert *x509.Certificate) []byte {
	buf := new(bytes.Buffer)
	if err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}); err != nil {
		panic(err)
	}

	return buf.Bytes()
}

func toDER(priv interface{}) []byte {
	var (
		der []byte
		err error
	)
	switch p := priv.(type) {
	case *rsa.PrivateKey:
		der = x509.MarshalPKCS1PrivateKey(p)
	case *ecdsa.PrivateKey:
		der, err = x509.MarshalECPrivateKey(p)
	default:
		err = errors.New("unknown key type")
	}
	if err != nil {
		panic(err)
	}

	return der
}

func toPKCS8(priv interface{}) []byte {
	cmd := exec.Command("openssl", "pkcs8", "-topk8", "-nocrypt", "-inform", "DER")

	cmd.Stdin = bytes.NewReader(toDER(priv))

	out := new(bytes.Buffer)
	cmd.Stdout = out

	if err := cmd.Run(); err != nil {
		panic(err)
	}

	return out.Bytes()
}
