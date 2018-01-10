// +build cgo

/*-
 * Copyright 2018 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
