package main

import (
	"crypto/tls"
)

func authorized(conn *tls.Conn) bool {
	// First up: check if we have a valid client certificate. We always require
	// a valid, signed client certificate to be present.
	if len(conn.ConnectionState().VerifiedChains) == 0 {
		logger.Printf("failed auth: client %s has no valid cert chain", conn.RemoteAddr())
		return false
	}

	// If --allow-all has been set, a valid cert is sufficient to connect.
	if *allowAll {
		return true
	}

	cert := conn.ConnectionState().VerifiedChains[0][0]

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

	logger.Printf("failed auth: client %s with subject '%s' has no matching CN or OU field", conn.RemoteAddr(), cert.Subject)

	return false
}
