package spiffetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

// Methods to generate private keys. If generation starts slowing down test
// execution then switch over to pre-generated keys.

// NewEC256Key returns an ECDSA key over the P256 curve
func NewEC256Key(tb testing.TB) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	return key
}
