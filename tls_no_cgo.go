// +build !cgo

package main

import (
	"crypto"
	"errors"
)

func newPKCS11(pubkey crypto.PublicKey) (crypto.PrivateKey, error) {
	panic(errors.New("PKCS11 unavailable when compiled without CGO support"))
}

func hasPKCS11() bool {
	return false
}
