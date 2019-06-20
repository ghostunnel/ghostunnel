// +build !cgo nopkcs11

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

package certloader

import "errors"

// SupportsPKCS11 returns true or false, depending on whether the binary
// was built with PKCS11 support or not (requires CGO to build).
func SupportsPKCS11() bool {
	return false
}

// CertificateFromPKCS11Module creates a reloadable certificate from a PKCS#11 module.
func CertificateFromPKCS11Module(certificatePath, caBundlePath, modulePath, tokenLabel, pin string) (Certificate, error) {
	return nil, errors.New("not supported")
}
