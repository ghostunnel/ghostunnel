// +build !certstore

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

// SupportsKeychain returns true or false, depending on whether the
// binary was built with Certstore/Keychain support or not (requires CGO, recent
// Darwin to build).
func SupportsKeychain() bool {
	return false
}

// CertificateFromKeychainIdentity creates a reloadable certificate from a system keychain identity.
func CertificateFromKeychainIdentity(commonName string, caBundlePath string) (Certificate, error) {
	return nil, errors.New("not supported")
}
