// +build !cgo

package main

import (
	"crypto"
	"fmt"
)

func newPKCS11(pubkey crypto.PublicKey) (crypto.PrivateKey, error) {
	return nil, fmt.Errorf("PKCS11 unavailable when compiled without CGO")
}

func hasPKCS11() bool {
	return false
}
