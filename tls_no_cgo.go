// +build !cgo

package main

import "fmt"

func newpkcs11(module, tokenlabel, pin, pubkey interface{}) (interface{}, error) {
	return nil, fmt.Errorf("PKCS11 unavailable when compiled without CGO")
}
