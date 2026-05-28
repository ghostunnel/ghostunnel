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

package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
)

func ExampleACL_server() {
	// Configure an access control list for incoming connections.
	acl := ACL{
		AllowedCNs: []string{
			// Allow peers with CN 'client1' or 'client2'
			"client1",
			"client2",
		},
	}

	// The VerifyPeerCertificate hook on crypto/tls is invoked synchronously
	// during the handshake. Wrap our context-aware ACL method in a closure
	// that supplies the appropriate context for OPA policy evaluation —
	// typically the proxy / listener lifetime context so the OPA query is
	// cancelled cleanly on shutdown.
	ctx := context.Background()
	_ = tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return acl.VerifyPeerCertificateServer(ctx, rawCerts, verifiedChains)
		},
	}
}

func ExampleACL_client() {
	// Configure an access control list for outgoing connections.
	acl := ACL{
		AllowedCNs: []string{
			// Allow peers with CN 'server1' or 'server2'
			"server1",
			"server2",
		},
	}

	// As with the server example, wrap the context-aware method in a closure
	// so the OPA evaluation honors the supplied context (here, the per-dial
	// context if you have one available).
	ctx := context.Background()
	_ = tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return acl.VerifyPeerCertificateClient(ctx, rawCerts, verifiedChains)
		},
	}
}
