package lib

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/fatih/color"
)

// TLSDescription has the basic information about a TLS connection
type TLSDescription struct {
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
}

// CertificateRequestInfo has the basic information about requested client certificates
type CertificateRequestInfo struct {
	AcceptableCAs    []simplePKIXName `json:"acceptable_issuers,omitempty"`
	SignatureSchemes []string         `json:"signature_schemes,omitempty"`
}

type tlsInfoContext struct {
	Conn *TLSDescription
	CRI  *CertificateRequestInfo
}

var tlsLayout = `** TLS Connection **
Version: {{.Conn.Version}}
Cipher Suite: {{.Conn.Cipher}}
{{- if .CRI}}

{{"Server has requested a client certificate:" | greenify}}
Acceptable issuers:
{{- range .CRI.AcceptableCAs}}
	{{.Name | printShortName}}{{end}}
Supported Signature Schemes:
{{- range .CRI.SignatureSchemes}}
	{{.}}{{end}}
{{- end}}`

func tlscolor(d description) string {
	c, ok := qualityColors[d.Quality]
	if !ok {
		return d.Name
	}
	return c.SprintFunc()(d.Name)
}

// EncodeTLSInfoToText returns a human readable string, suitable for certigo console output.
func EncodeTLSInfoToText(tcs *tls.ConnectionState, cri *tls.CertificateRequestInfo) string {
	version := lookup(tlsVersions, tcs.Version)
	cipher := lookup(cipherSuites, tcs.CipherSuite)
	description := TLSDescription{
		Version: tlscolor(version),
		Cipher:  tlscolor(explainCipher(cipher)),
	}
	tlsInfoContext := tlsInfoContext{
		Conn: &description,
	}
	if cri != nil {
		criDesc, err := EncodeCRIToObject(cri)
		if err == nil {
			tlsInfoContext.CRI = criDesc.(*CertificateRequestInfo)
		}
	}

	funcMap := sprig.TxtFuncMap()
	extras := template.FuncMap{
		"printShortName": PrintShortName,
		"greenify":       greenify,
	}
	for k, v := range extras {
		funcMap[k] = v
	}

	t := template.New("TLS template").Funcs(funcMap)
	t, err := t.Parse(tlsLayout)
	if err != nil {
		// Should never happen
		panic(err)
	}
	var buffer bytes.Buffer
	w := bufio.NewWriter(&buffer)
	err = t.Execute(w, tlsInfoContext)
	if err != nil {
		// Should never happen
		panic(err)
	}
	w.Flush()
	return string(buffer.Bytes())
}

// EncodeTLSToObject returns a JSON-marshallable description of a TLS connection
func EncodeTLSToObject(t *tls.ConnectionState) interface{} {
	version := lookup(tlsVersions, t.Version)
	cipher := lookup(cipherSuites, t.CipherSuite)
	return &TLSDescription{
		version.Slug,
		cipher.Slug,
	}
}

// EncodeCRIToObject returns a JSON-marshallable representation of a CertificateRequestInfo object.
func EncodeCRIToObject(cri *tls.CertificateRequestInfo) (interface{}, error) {
	out := &CertificateRequestInfo{}
	for _, ca := range cri.AcceptableCAs {
		subject, err := parseRawSubject(ca)
		if err != nil {
			return nil, err
		}
		out.AcceptableCAs = append(out.AcceptableCAs, simplePKIXName{subject, nil})
	}
	for _, scheme := range cri.SignatureSchemes {
		desc, ok := signatureSchemeStrings[scheme]
		if !ok {
			desc = fmt.Sprintf("Unknown(0x%x)", scheme)
		}
		out.SignatureSchemes = append(out.SignatureSchemes, desc)
	}
	return out, nil
}

// Just a map lookup with a default
func lookup(descriptions map[uint16]description, what uint16) description {
	v, ok := descriptions[what]
	if !ok {
		unknown := fmt.Sprintf("UNKNOWN_%x", what)
		return description{unknown, unknown, 0}
	}
	return v
}

const (
	insecure = iota
	ok       = iota
	good     = iota
)

type description struct {
	Name    string // a human-friendly string
	Slug    string // a machine-friendly string
	Quality uint8  // insecure, ok, good
}

var qualityColors = map[uint8]*color.Color{
	insecure: red,
	ok:       yellow,
	good:     green,
}

var tlsVersions = map[uint16]description{
	tls.VersionSSL30: {"SSL 3.0", "ssl_3_0", insecure},
	tls.VersionTLS10: {"TLS 1.0", "tls_1_0", insecure},
	tls.VersionTLS11: {"TLS 1.1", "tls_1_1", ok},
	tls.VersionTLS12: {"TLS 1.2", "tls_1_2", good},
}

func parseRawSubject(subject []byte) (pkix.Name, error) {
	name := pkix.Name{}

	var seq pkix.RDNSequence
	_, err := asn1.Unmarshal(subject, &seq)
	if err != nil {
		return name, err
	}

	name.FillFromRDNSequence(&seq)
	return name, nil
}

// Fill in a human readable name, extracted from the slug
func explainCipher(d description) description {
	kexAndCipher := strings.Split(d.Slug, "_WITH_")
	d.Name = fmt.Sprintf("%s key exchange, %s cipher", kexAndCipher[0][len("TLS_"):], kexAndCipher[1])
	return d
}

var cipherSuites = map[uint16]description{
	tls.TLS_RSA_WITH_RC4_128_SHA:                {"", "TLS_RSA_WITH_RC4_128_SHA", insecure},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           {"", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", insecure},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:            {"", "TLS_RSA_WITH_AES_128_CBC_SHA", ok},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:            {"", "TLS_RSA_WITH_AES_256_CBC_SHA", ok},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         {"", "TLS_RSA_WITH_AES_128_CBC_SHA256", ok},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         {"", "TLS_RSA_WITH_AES_128_GCM_SHA256", ok},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         {"", "TLS_RSA_WITH_AES_256_GCM_SHA384", ok},
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        {"", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", insecure},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    {"", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", ok},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    {"", "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", ok},
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          {"", "TLS_ECDHE_RSA_WITH_RC4_128_SHA", insecure},
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     {"", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", insecure},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      {"", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", ok},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      {"", "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", ok},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: {"", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", ok},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   {"", "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", ok},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   {"", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", good},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: {"", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", good},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   {"", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", good},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: {"", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", good},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    {"", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305", good},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  {"", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305", good},
}
