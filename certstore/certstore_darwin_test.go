//go:build darwin && cgo

package certstore

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAlgoUnsupportedHashRSAPSS(t *testing.T) {
	withIdentity(t, leafRSA, func(ident Identity) {
		mi, ok := ident.(*macIdentity)
		require.True(t, ok, "expected *macIdentity")

		_, err := mi.getAlgo(crypto.SHA224, &rsa.PSSOptions{Hash: crypto.SHA224})
		assert.ErrorIs(t, err, ErrUnsupportedHash)
	})
}

func TestGetAlgoUnsupportedHashECDSA(t *testing.T) {
	withIdentity(t, leafEC, func(ident Identity) {
		mi, ok := ident.(*macIdentity)
		require.True(t, ok)

		_, err := mi.getAlgo(crypto.SHA224, crypto.SHA224)
		assert.ErrorIs(t, err, ErrUnsupportedHash)
	})
}

func TestOsStatusErrorNonZero(t *testing.T) {
	err := errSecItemNotFound
	require.Error(t, err)
	assert.Contains(t, err.Error(), "OSStatus")
	assert.Contains(t, err.Error(), "-25300")
}

// TestAlgoForPublicKeyUnsupportedKeyType exercises the default branch of the
// public-key type switch in algoForPublicKey (extracted from getAlgo) using
// an Ed25519 public key, which Apple's Security framework does not support
// for SecKeyCreateSignature. This avoids the keychain-import path entirely
// since SecPKCS12Import on macOS does not accept Ed25519 keys.
func TestAlgoForPublicKeyUnsupportedKeyType(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	_, err = algoForPublicKey(pub, crypto.SHA256, crypto.SHA256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}
