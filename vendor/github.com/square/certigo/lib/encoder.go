/*-
 * Copyright 2016 Square Inc.
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

package lib

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var keyUsages = []x509.KeyUsage{
	x509.KeyUsageDigitalSignature,
	x509.KeyUsageContentCommitment,
	x509.KeyUsageKeyEncipherment,
	x509.KeyUsageDataEncipherment,
	x509.KeyUsageKeyAgreement,
	x509.KeyUsageCertSign,
	x509.KeyUsageCRLSign,
	x509.KeyUsageEncipherOnly,
	x509.KeyUsageDecipherOnly,
}

var keyUsageStrings = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "Digital Signature",
	x509.KeyUsageContentCommitment: "Content Commitment",
	x509.KeyUsageKeyEncipherment:   "Key Encipherment",
	x509.KeyUsageDataEncipherment:  "Data Encipherment",
	x509.KeyUsageKeyAgreement:      "Key Agreement",
	x509.KeyUsageCertSign:          "Cert Sign",
	x509.KeyUsageCRLSign:           "CRL Sign",
	x509.KeyUsageEncipherOnly:      "Encipher Only",
	x509.KeyUsageDecipherOnly:      "Decipher Only",
}

var extKeyUsageStrings = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "Any",
	x509.ExtKeyUsageServerAuth:                 "Server Auth",
	x509.ExtKeyUsageClientAuth:                 "Client Auth",
	x509.ExtKeyUsageCodeSigning:                "Code Signing",
	x509.ExtKeyUsageEmailProtection:            "Email Protection",
	x509.ExtKeyUsageIPSECEndSystem:             "IPSEC End System",
	x509.ExtKeyUsageIPSECTunnel:                "IPSEC Tunnel",
	x509.ExtKeyUsageIPSECUser:                  "IPSEC User",
	x509.ExtKeyUsageTimeStamping:               "Time Stamping",
	x509.ExtKeyUsageOCSPSigning:                "OCSP Signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "Microsoft ServerGatedCrypto",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "Netscape ServerGatedCrypto",
}

var algoName = [...]string{
	x509.MD2WithRSA:      "MD2-RSA",
	x509.MD5WithRSA:      "MD5-RSA",
	x509.SHA1WithRSA:     "SHA1-RSA",
	x509.SHA256WithRSA:   "SHA256-RSA",
	x509.SHA384WithRSA:   "SHA384-RSA",
	x509.SHA512WithRSA:   "SHA512-RSA",
	x509.DSAWithSHA1:     "DSA-SHA1",
	x509.DSAWithSHA256:   "DSA-SHA256",
	x509.ECDSAWithSHA1:   "ECDSA-SHA1",
	x509.ECDSAWithSHA256: "ECDSA-SHA256",
	x509.ECDSAWithSHA384: "ECDSA-SHA384",
	x509.ECDSAWithSHA512: "ECDSA-SHA512",
}

type basicConstraints struct {
	IsCA       bool `json:"is_ca"`
	MaxPathLen *int `json:"pathlen,omitempty"`
}

type nameConstraints struct {
	Critical            bool     `json:"critical,omitempty"`
	PermittedDNSDomains []string `json:"permitted_dns_domains,omitempty"`
}

// simpleCertificate is a JSON-representable certificate metadata holder.
type simpleCertificate struct {
	Alias              string              `json:"alias,omitempty"`
	SerialNumber       string              `json:"serial"`
	NotBefore          time.Time           `json:"not_before"`
	NotAfter           time.Time           `json:"not_after"`
	SignatureAlgorithm simpleSigAlg        `json:"signature_algorithm"`
	IsSelfSigned       bool                `json:"is_self_signed"`
	Subject            simplePKIXName      `json:"subject"`
	Issuer             simplePKIXName      `json:"issuer"`
	BasicConstraints   *basicConstraints   `json:"basic_constraints,omitempty"`
	NameConstraints    *nameConstraints    `json:"name_constraints,omitempty"`
	KeyUsage           simpleKeyUsage      `json:"key_usage,omitempty"`
	ExtKeyUsage        []simpleExtKeyUsage `json:"extended_key_usage,omitempty"`
	AltDNSNames        []string            `json:"dns_names,omitempty"`
	AltIPAddresses     []net.IP            `json:"ip_addresses,omitempty"`
	EmailAddresses     []string            `json:"email_addresses,omitempty"`
	Warnings           []string            `json:"warnings,omitempty"`
	PEM                string              `json:"pem,omitempty"`
}

type simplePKIXName struct {
	Name  pkix.Name
	KeyID []byte
}

type simpleKeyUsage x509.KeyUsage
type simpleExtKeyUsage x509.ExtKeyUsage

type simpleSigAlg x509.SignatureAlgorithm

func createSimpleCertificate(name string, cert *x509.Certificate) simpleCertificate {
	out := simpleCertificate{
		Alias:              name,
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: simpleSigAlg(cert.SignatureAlgorithm),
		IsSelfSigned:       IsSelfSigned(cert),
		Subject: simplePKIXName{
			Name:  cert.Subject,
			KeyID: cert.SubjectKeyId,
		},
		Issuer: simplePKIXName{
			Name:  cert.Issuer,
			KeyID: cert.AuthorityKeyId,
		},
		KeyUsage:       simpleKeyUsage(cert.KeyUsage),
		AltDNSNames:    cert.DNSNames,
		AltIPAddresses: cert.IPAddresses,
		EmailAddresses: cert.EmailAddresses,
		Warnings:       certWarnings(cert),
		PEM:            string(pem.EncodeToMemory(EncodeX509ToPEM(cert, nil))),
	}

	if cert.BasicConstraintsValid {
		out.BasicConstraints = &basicConstraints{
			IsCA: cert.IsCA,
		}
		if cert.MaxPathLen > 0 || cert.MaxPathLenZero {
			out.BasicConstraints.MaxPathLen = &cert.MaxPathLen
		}
	}

	if len(cert.PermittedDNSDomains) > 0 {
		out.NameConstraints = &nameConstraints{
			Critical:            cert.PermittedDNSDomainsCritical,
			PermittedDNSDomains: cert.PermittedDNSDomains,
		}
	}

	simpleEku := []simpleExtKeyUsage{}
	for _, eku := range cert.ExtKeyUsage {
		simpleEku = append(simpleEku, simpleExtKeyUsage(eku))
	}
	out.ExtKeyUsage = simpleEku

	return out
}

func (p simplePKIXName) MarshalJSON() ([]byte, error) {
	out := map[string]interface{}{}

	if p.Name.CommonName != "" {
		out["common_name"] = p.Name.CommonName
	}
	if len(p.Name.Organization) > 0 {
		out["organization"] = p.Name.Organization
	}
	if len(p.Name.OrganizationalUnit) > 0 {
		out["organizational_unit"] = p.Name.OrganizationalUnit
	}
	if len(p.Name.Country) > 0 {
		out["country"] = p.Name.Country
	}
	if len(p.Name.Locality) > 0 {
		out["locality"] = p.Name.Locality
	}
	if len(p.KeyID) > 0 {
		out["key_id"] = hexify(p.KeyID)
	}

	return json.Marshal(out)
}

func (k simpleKeyUsage) MarshalJSON() ([]byte, error) {
	return json.Marshal(keyUsage(k))
}

func (e simpleExtKeyUsage) MarshalJSON() ([]byte, error) {
	return json.Marshal(extKeyUsage(e))
}

func (s simpleSigAlg) MarshalJSON() ([]byte, error) {
	return json.Marshal(algString(x509.SignatureAlgorithm(s)))
}

// hexify returns a colon separated, hexadecimal representation
// of a given byte array.
func hexify(arr []byte) string {
	var hexed bytes.Buffer
	for i := 0; i < len(arr); i++ {
		hexed.WriteString(strings.ToUpper(hex.EncodeToString(arr[i : i+1])))
		if i < len(arr)-1 {
			hexed.WriteString(":")
		}
	}
	return hexed.String()
}

// keyUsage decodes/prints key usage from a certificate.
func keyUsage(sKu simpleKeyUsage) []string {
	ku := x509.KeyUsage(sKu)
	out := []string{}
	for _, key := range keyUsages {
		if ku&key > 0 {
			out = append(out, keyUsageStrings[key])
		}
	}
	return out
}

// extKeyUsage decodes/prints extended key usage from a certificate.
func extKeyUsage(sEku simpleExtKeyUsage) string {
	eku := x509.ExtKeyUsage(sEku)
	val, ok := extKeyUsageStrings[eku]
	if ok {
		return val
	}
	return fmt.Sprintf("unknown:%d", eku)
}

func algString(algo x509.SignatureAlgorithm) string {
	if 0 < algo && int(algo) < len(algoName) {
		return algoName[algo]
	}
	return strconv.Itoa(int(algo))
}

// decodeKey returns the algorithm and key size for a public key.
func decodeKey(publicKey interface{}) (string, int) {
	switch publicKey.(type) {
	case *dsa.PublicKey:
		return "DSA", publicKey.(*dsa.PublicKey).P.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", publicKey.(*ecdsa.PublicKey).Curve.Params().BitSize
	case *rsa.PublicKey:
		return "RSA", publicKey.(*rsa.PublicKey).N.BitLen()
	default:
		return "", 0
	}
}

// certWarnings prints a list of warnings to show common mistakes in certs.
func certWarnings(cert *x509.Certificate) (warnings []string) {
	if cert.SerialNumber.Sign() != 1 {
		warnings = append(warnings, "Serial number in cert appears to be zero/negative")
	}

	if cert.SerialNumber.BitLen() > 160 {
		warnings = append(warnings, "Serial number too long; should be 20 bytes or less")
	}

	if (cert.KeyUsage&x509.KeyUsageCertSign != 0) && !cert.IsCA {
		warnings = append(warnings, "Key usage 'cert sign' is set, but is not a CA cert")
	}

	if (cert.KeyUsage&x509.KeyUsageCertSign == 0) && cert.IsCA {
		warnings = append(warnings, "Certificate is a CA cert, but key usage 'cert sign' missing")
	}

	if cert.Version < 2 {
		warnings = append(warnings, fmt.Sprintf("Certificate is not in X509v3 format (version is %d)", cert.Version+1))
	}

	if len(cert.UnhandledCriticalExtensions) > 0 {
		warnings = append(warnings, "Certificate has unhandled critical extensions")
	}

	warnings = append(warnings, algWarnings(cert)...)

	return
}

// algWarnings checks key sizes, signature algorithms.
func algWarnings(cert *x509.Certificate) (warnings []string) {
	alg, size := decodeKey(cert.PublicKey)
	if (alg == "RSA" || alg == "DSA") && size < 2048 {
		warnings = append(warnings, fmt.Sprintf("Size of %s key should be at least 2048 bits", alg))
	}
	if alg == "ECDSA" && size < 224 {
		warnings = append(warnings, fmt.Sprintf("Size of %s key should be at least 224 bits", alg))
	}

	for _, alg := range badSignatureAlgorithms {
		if cert.SignatureAlgorithm == alg {
			warnings = append(warnings, fmt.Sprintf("Using %s, which is an outdated signature algorithm", algString(alg)))
		}
	}

	if alg == "RSA" {
		key := cert.PublicKey.(*rsa.PublicKey)
		if key.E < 3 {
			warnings = append(warnings, "Public key exponent in RSA key is less than 3")
		}
		if key.N.Sign() != 1 {
			warnings = append(warnings, "Public key modulus in RSA key appears to be zero/negative")
		}
	}

	return
}

// IsSelfSigned returns true iff the given certificate has a valid self-signature.
func IsSelfSigned(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(cert) == nil
}
