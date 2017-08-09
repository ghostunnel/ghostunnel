// +build cgo

package main

import (
	"crypto"

	"github.com/letsencrypt/pkcs11key"
)

var (
	pkcs11Module     = app.Flag("pkcs11-module", "Path to PKCS11 module (SO) file (optional)").PlaceHolder("PATH").ExistingFile()
	pkcs11TokenLabel = app.Flag("pkcs11-token-label", "Token label for slot/key in PKCS11 module (optional)").PlaceHolder("LABEL").String()
	pkcs11PIN        = app.Flag("pkcs11-pin", "PIN code for slot/key in PKCS11 module (optional)").PlaceHolder("PIN").String()
)

func newPKCS11(pubkey crypto.PublicKey) (crypto.PrivateKey, error) {
	return pkcs11key.New(*pkcs11Module, *pkcs11TokenLabel, *pkcs11PIN, pubkey)
}

func hasPKCS11() bool {
	return *pkcs11Module != ""
}
