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

import "crypto/tls"

func ExampleCertificate() {
	// Load a certificate from a set of PEM files.
	cert, _ := CertificateFromPEMFiles("/path/to/cert.pem", "/path/to/privatekey.pem", "/path/to/cacert.pem")

	// Use the certificate in a tls.Config for servers
	_ = tls.Config{
		// The GetCertificate function will be called to retrieve the latest
		// certificate when receiving new connections.
		GetCertificate: cert.GetCertificate,
	}

	// Use the certificate in a tls.Config for clients
	_ = tls.Config{
		// The GetClientCertificate function will be called to retrieve the latest
		// client certificate when making new connections.
		GetClientCertificate: cert.GetClientCertificate,
	}

	// Reload a certificate. Will re-read the files from disk, and update the
	// certificate if there have been any changes.
	cert.Reload()
}
