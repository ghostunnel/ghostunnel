package spiffe

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/internal"
)

// VerifyPeerCertificate verifies the provided peer certificate chain using the
// set trust domain roots. The expectPeerFn callback is used to check the peer
// ID after the chain of trust has been verified to assert that the chain
// belongs to the intended peer.
func VerifyPeerCertificate(peerChain []*x509.Certificate, trustDomainRoots map[string]*x509.CertPool, expectPeerFn ExpectPeerFunc) ([][]*x509.Certificate, error) {
	switch {
	case len(peerChain) == 0:
		return nil, errors.New("no peer certificates")
	case len(trustDomainRoots) == 0:
		return nil, errors.New("at least one trust domain root is required")
	case expectPeerFn == nil:
		return nil, errors.New("expectPeerFn callback is required")
	}

	peer := peerChain[0]
	peerID, trustDomainID, err := getIDsFromCertificate(peer)
	if err != nil {
		return nil, err
	}

	roots, ok := trustDomainRoots[trustDomainID]
	if !ok {
		return nil, fmt.Errorf("no roots for peer trust domain %q", trustDomainID)
	}

	verifiedChains, err := peer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: internal.CertPoolFromCerts(peerChain[1:]),
		// TODO: assert client or server depending on role?
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, err
	}

	if err := expectPeerFn(peerID, verifiedChains); err != nil {
		return nil, err
	}

	return verifiedChains, nil
}
