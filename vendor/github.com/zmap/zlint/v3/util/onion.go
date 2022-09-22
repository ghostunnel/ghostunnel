package util

import (
	"encoding/base32"
	"strings"

	"github.com/zmap/zcrypto/x509"
)

// An onion V3 address is base32 encoded, however Tor believes that the standard base32 encoding
// is lowercase while the Go standard library believes that the standard base32 encoding is uppercase.
//
// onionV3Base32Encoding is simply base32.StdEncoding but lowercase instead of uppercase in order
// to work with the above mismatch.
var onionV3Base32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")

// IsOnionV3 returns whether or not the provided DNS name is an Onion V3 encoded address.
//
// In order to be an Onion V3 encoded address, the DNS name must satisfy the following:
//  1. Contain at least two labels.
//  2. The right most label MUST be "onion".
//  3. The second to the right most label MUST be exactly 56 characters long.
//  4. The second to the right most label MUST be base32 encoded against the lowercase standard encoding.
//  5. The final byte of the decoded result from #4 MUST be equal to 0x03.
func IsOnionV3(dnsName string) bool {
	labels := strings.Split(dnsName, ".")
	if len(labels) < 2 || labels[len(labels)-1] != "onion" {
		return false
	}
	address := labels[len(labels)-2]
	if len(address) != 56 {
		return false
	}
	raw, err := onionV3Base32Encoding.DecodeString(address)
	if err != nil {
		return false
	}
	return raw[len(raw)-1] == 0x03
}

// AllAreOnionV3 returns whether-or-not EVERY name provided conforms to IsOnionV3
func AllAreOnionV3(names []string) bool {
	isV3 := !(len(names) == 0)
	for _, name := range names {
		isV3 = isV3 && IsOnionV3(name)
	}
	return isV3
}

// IsOnionV3Cert returns whether-or-not the provided certificates' subject common name and
// ALL subject alternative DNS names are version 3 Onion addresses.
func IsOnionV3Cert(c *x509.Certificate) bool {
	return AllAreOnionV3(append(c.DNSNames, c.Subject.CommonName))
}
