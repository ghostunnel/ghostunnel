package main

import (
	"crypto/tls"
)

func authorized(conn *tls.Conn) bool {
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, clientOU := range chain[0].Subject.OrganizationalUnit {
			for _, expectedOU := range *clientNames {
				if clientOU == expectedOU {
					return true
				}
			}

			logger.Printf("client OU %s is not in %s", clientOU, *clientNames)
		}
	}

	return false
}
