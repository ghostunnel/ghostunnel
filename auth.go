/*-
 * Copyright 2015 Square Inc.
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
	"crypto/tls"
)

func authorized(conn tls.ConnectionState) bool {
	// First up: check if we have a valid client certificate. We always require
	// a valid, signed client certificate to be present.
	if len(conn.VerifiedChains) == 0 {
		return false
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if *allowAll {
		return true
	}

	cert := conn.VerifiedChains[0][0]

	// Check CN against --allow-cn flag(s).
	for _, expectedCN := range *allowedCNs {
		if cert.Subject.CommonName == expectedCN {
			return true
		}
	}

	// Check OUs against --allow-ou flag(s).
	for _, clientOU := range cert.Subject.OrganizationalUnit {
		for _, expectedOU := range *allowedOUs {
			if clientOU == expectedOU {
				return true
			}
		}
	}

	return false
}
