package spiffe

import (
	"crypto/x509"
	"fmt"
	"net/url"
)

// ExpectPeerFunc is invoked after peer SVID verification to validate the SVID
// belongs to th indended peer. If an error is returned, verification (i.e. TLS
// handshake) fails.
type ExpectPeerFunc func(peerID string, verifiedChains [][]*x509.Certificate) error

// ExpectAnyPeer allows any peer
func ExpectAnyPeer() ExpectPeerFunc {
	return func(string, [][]*x509.Certificate) error {
		return nil
	}
}

// ExpectPeer allows a peer matching the specified peer ID
func ExpectPeer(expectedID string) ExpectPeerFunc {
	return func(peerID string, _ [][]*x509.Certificate) error {
		if peerID != expectedID {
			return fmt.Errorf("unexpected peer ID %q", peerID)
		}
		return nil
	}
}

// ExpectPeers allows any peer to belong to the provided set.
func ExpectPeers(expectedIDs ...string) ExpectPeerFunc {
	m := make(map[string]struct{}, len(expectedIDs))
	for _, id := range expectedIDs {
		m[id] = struct{}{}
	}
	return func(peerID string, _ [][]*x509.Certificate) error {
		if _, ok := m[peerID]; !ok {
			return fmt.Errorf("unexpected peer ID %q", peerID)
		}
		return nil
	}
}

// ExpectPeerInDomain returns a callback that asserts that the peer ID belongs
// to the provided trust domain (i.e. "domain.test")
func ExpectPeerInDomain(expectedDomain string) ExpectPeerFunc {
	return func(peerID string, _ [][]*x509.Certificate) error {
		if domain := getPeerTrustDomain(peerID); domain != expectedDomain {
			return fmt.Errorf("unexpected peer trust domain %q", domain)
		}
		return nil
	}
}

func getPeerTrustDomain(peerID string) string {
	u, _ := url.Parse(peerID)
	if u != nil {
		return u.Host
	}
	return ""
}
