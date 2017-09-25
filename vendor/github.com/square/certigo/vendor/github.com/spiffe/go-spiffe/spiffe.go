package spiffe

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
)

var oidExtensionSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

func getURINamesFromSANExtension(sanExtension []byte) (uris []string, err error) {
	// RFC 5280, 4.2.1.6

	// SubjectAltName ::= GeneralNames
	//
	// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
	//
	// GeneralName ::= CHOICE {
	//      otherName                       [0]     OtherName,
	//      rfc822Name                      [1]     IA5String,
	//      dNSName                         [2]     IA5String,
	//      x400Address                     [3]     ORAddress,
	//      directoryName                   [4]     Name,
	//      ediPartyName                    [5]     EDIPartyName,
	//      uniformResourceIdentifier       [6]     IA5String,
	//      iPAddress                       [7]     OCTET STRING,
	//      registeredID                    [8]     OBJECT IDENTIFIER }
	var seq asn1.RawValue
	var rest []byte
	if rest, err = asn1.Unmarshal(sanExtension, &seq); err != nil {
		return
	} else if len(rest) != 0 {
		err = errors.New("x509: trailing data after X.509 extension")
		return
	}
	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		err = asn1.StructuralError{Msg: "bad SAN sequence"}
		return
	}

	rest = seq.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return
		}
		if v.Tag == 6 {
			uris = append(uris, string(v.Bytes))
		}
	}

	return
}

func getExtensionsFromAsn1ObjectIdentifier(certificate *x509.Certificate, id asn1.ObjectIdentifier) []pkix.Extension {
	var extensions []pkix.Extension

	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(id) {
			extensions = append(extensions, extension)
		}
	}

	return extensions
}

// GetUrisInSubjectAltName takes a parsed X.509 certificate and gets the URIs from the SAN extension.
func GetURINamesFromCertificate(cert *x509.Certificate) (uris []string, err error) {
	for _, ext := range getExtensionsFromAsn1ObjectIdentifier(cert, oidExtensionSubjectAltName) {
		uris, err = getURINamesFromSANExtension(ext.Value)
		if err != nil {
			return
		}
	}

	return uris, nil
}

// GetUrisInSubjectAltNameEncoded parses a PEM-encoded X.509 certificate and gets the URIs from the SAN extension.
func GetURINamesFromPEM(encodedCertificate string) (uris []string, err error) {
	block, _ := pem.Decode([]byte(encodedCertificate))
	if block == nil {
		return uris, errors.New("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return uris, errors.New("failed to parse certificate: " + err.Error())
	}

	return GetURINamesFromCertificate(cert)
}
