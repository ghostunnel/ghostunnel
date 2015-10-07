package main

import (
	"net"
)

// Helper function to decode a *net.TCPAddr into a tuple of network and
// address. Must use this since kavu/so_reuseport does not currently
// support passing "tcp" to support for IPv4 and IPv6. We must pass "tcp4"
// or "tcp6" explicitly.
func decodeAddress(tuple *net.TCPAddr) (network, address string) {
	if tuple.IP.To4() != nil {
		network = "tcp4"
	} else {
		network = "tcp6"
	}

	address = tuple.String()
	return
}
