// +build cgo

package main

import "crypto"
import "github.com/letsencrypt/pkcs11key"


func newpkcs11(module, tokenLabel, pin string, pubkey crypto.PublicKey) (interface{}, error) {
	return pkcs11key.New(module, tokenLabel, pin, pubkey)
}
