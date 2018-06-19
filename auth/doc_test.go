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

import "crypto/tls"

func ExampleACL_server() {
	// Configure an access control list for incoming connections.
	acl := ACL{
		AllowedCNs: []string{
			// Allow peers with CN 'client1' or 'client2'
			"client1",
			"client2",
		},
	}

	// Example tls.Config for a TLS server.
	_ = tls.Config{
		// Set VerifyPeerCertificate on our tls.Config to point to our access
		// control list. When accepting connections on a TLS listener with this
		// config, Go will call our verify function and pass the peer certificates
		// as an argument. The ACL implementation will check that the peer has one
		// of the attributes configured in the ACL before allowing the connection
		// to proceed.
		VerifyPeerCertificate: acl.VerifyPeerCertificateServer,
	}
}

func ExampleACL_client() {
	// Configure an access control list for incoming connections.
	acl := ACL{
		AllowedCNs: []string{
			// Allow peers with CN 'server1' or 'server2'
			"server1",
			"server2",
		},
	}

	// Example tls.Config for a TLS server.
	_ = tls.Config{
		// Set VerifyPeerCertificate on our tls.Config to point to our access
		// control list. When initiating connections to a TLS server with this
		// config, Go will call our verify function and pass the peer certificates
		// as an argument. The ACL implementation will check that the peer has one
		// of the attributes configured in the ACL before allowing the connection
		// to proceed.
		VerifyPeerCertificate: acl.VerifyPeerCertificateClient,
	}
}
