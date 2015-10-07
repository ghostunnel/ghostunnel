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
