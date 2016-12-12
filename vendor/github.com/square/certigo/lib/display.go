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
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"text/template"
	"time"

	"github.com/fatih/color"
)

var layout = `{{if .Alias}}{{.Alias}}
{{end}}Serial: {{.SerialNumber}}
Not Before: {{.NotBefore | certStart}}
Not After : {{.NotAfter | certEnd}}
Signature : {{.SignatureAlgorithm | highlightAlgorithm}}{{if .IsSelfSigned}} (self-signed){{end}}
Subject Info:{{if .Subject.Name.CommonName}}
	CommonName: {{.Subject.Name.CommonName}}{{end}}{{if .Subject.Name.Organization}}
	Organization: {{.Subject.Name.Organization}}{{end}}{{if .Subject.Name.OrganizationalUnit}}
	OrganizationalUnit: {{.Subject.Name.OrganizationalUnit}}{{end}}{{if .Subject.Name.Country}}
	Country: {{.Subject.Name.Country}}{{end}}{{if .Subject.Name.Locality}}
	Locality: {{.Subject.Name.Locality}}{{end}}
Issuer Info:{{if .Issuer.Name.CommonName}}
	CommonName: {{.Issuer.Name.CommonName}}{{end}}{{if .Issuer.Name.Organization}}
	Organization: {{.Issuer.Name.Organization}}{{end}}{{if .Issuer.Name.OrganizationalUnit}}
	OrganizationalUnit: {{.Issuer.Name.OrganizationalUnit}}{{end}}{{if .Issuer.Name.Country}}
	Country: {{.Issuer.Name.Country}}{{end}}{{if .Issuer.Name.Locality}}
	Locality: {{.Issuer.Name.Locality}}{{end}}{{if .Subject.KeyID}}
Subject Key ID   : {{.Subject.KeyID | hexify}}{{end}}{{if .Issuer.KeyID}}
Authority Key ID : {{.Issuer.KeyID | hexify}}{{end}}{{if .BasicConstraints}}
Basic Constraints: CA:{{.BasicConstraints.IsCA}}{{if .BasicConstraints.MaxPathLen}}, pathlen:{{.BasicConstraints.MaxPathLen}}{{end}}{{end}}{{if .NameConstraints}}
Name Constraints {{if .PermittedDNSDomains.Critical}}(critical){{end}}: {{range .NameConstraints.PermittedDNSDomains}}
	{{.}}{{end}}{{end}}{{if .KeyUsage}}
Key Usage:{{range .KeyUsage | keyUsage}}
	{{.}}{{end}}{{end}}{{if .ExtKeyUsage}}
Extended Key Usage:{{range .ExtKeyUsage}}
	{{. | extKeyUsage}}{{end}}{{end}}{{if .AltDNSNames}}
Alternate DNS Names:{{range .AltDNSNames}}
	{{.}}{{end}}{{end}}{{if .AltIPAddresses}}
Alternate IP Addresses:{{range .AltIPAddresses}}
	{{.}}{{end}}{{end}}{{if .EmailAddresses}}
Email Addresses:{{range .EmailAddresses}}
	{{.}}{{end}}{{end}}{{if .Warnings}}
Warnings:{{range .Warnings}}
	{{. | redify}}{{end}}{{end}}`

type certWithName struct {
	name string
	file string
	cert *x509.Certificate
}

func (c certWithName) MarshalJSON() ([]byte, error) {
	out := createSimpleCertificate(c.name, c.cert)
	return json.Marshal(out)
}

func createSimpleCertificateFromX509(block *pem.Block) (simpleCertificate, error) {
	raw, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return simpleCertificate{}, fmt.Errorf("error reading cert: %s", err)
	}

	cert := certWithName{cert: raw}
	if val, ok := block.Headers[nameHeader]; ok {
		cert.name = val
	}
	if val, ok := block.Headers[fileHeader]; ok {
		cert.file = val
	}

	return createSimpleCertificate(cert.name, cert.cert), nil
}

// EncodeX509ToJSON encodes an X.509 certificate into a JSON string.
func EncodeX509ToJSON(cert *x509.Certificate) []byte {
	out := createSimpleCertificate("", cert)
	raw, err := json.Marshal(out)
	if err != nil {
		panic(err)
	}
	return raw
}

// EncodeX509ToObject encodes an X.509 certificate into a JSON-serializable object.
func EncodeX509ToObject(cert *x509.Certificate) interface{} {
	return createSimpleCertificate("", cert)
}

// EncodeX509ToText encodes an X.509 certificate into human-readable text.
func EncodeX509ToText(cert *x509.Certificate) []byte {
	return displayCert(createSimpleCertificate("", cert))
}

// displayCert takes in a parsed certificate object
// (for jceks certs, blank otherwise), and prints out relevant
// information. Start and end dates are colored based on whether or not
// the certificate is expired, not expired, or close to expiring.
func displayCert(cert simpleCertificate) []byte {
	funcMap := template.FuncMap{
		"certStart":          certStart,
		"certEnd":            certEnd,
		"redify":             redify,
		"highlightAlgorithm": highlightAlgorithm,
		"hexify":             hexify,
		"keyUsage":           keyUsage,
		"extKeyUsage":        extKeyUsage,
	}
	t := template.New("Cert template").Funcs(funcMap)
	t, err := t.Parse(layout)
	if err != nil {
		// Should never happen
		panic(err)
	}
	var buffer bytes.Buffer
	w := bufio.NewWriter(&buffer)
	err = t.Execute(w, cert)
	if err != nil {
		// Should never happen
		panic(err)
	}
	w.Flush()
	return buffer.Bytes()
}

var (
	green  = color.New(color.Bold, color.FgGreen)
	yellow = color.New(color.Bold, color.FgYellow)
	red    = color.New(color.Bold, color.FgRed)
)

var algorithmColors = map[x509.SignatureAlgorithm]*color.Color{
	x509.MD2WithRSA:      red,
	x509.MD5WithRSA:      red,
	x509.SHA1WithRSA:     red,
	x509.SHA256WithRSA:   green,
	x509.SHA384WithRSA:   green,
	x509.SHA512WithRSA:   green,
	x509.DSAWithSHA1:     red,
	x509.DSAWithSHA256:   red,
	x509.ECDSAWithSHA1:   red,
	x509.ECDSAWithSHA256: green,
	x509.ECDSAWithSHA384: green,
	x509.ECDSAWithSHA512: green,
}

// highlightAlgorithm changes the color of the signing algorithm
// based on a set color map, e.g. to make SHA-1 show up red.
func highlightAlgorithm(sigAlg simpleSigAlg) string {
	sig := x509.SignatureAlgorithm(sigAlg)
	color, ok := algorithmColors[sig]
	if !ok {
		return algString(sig)
	}
	return color.SprintFunc()(algString(sig))
}

// certStart takes a given start time for the validity of
// a certificate and returns that time colored properly
// based on how close it is to expiry. If it's more than
// a day after the certificate became valid the string will
// be green. If it has been less than a day the string will
// be yellow. If the certificate is not yet valid, the string
// will be red.
func certStart(start time.Time) string {
	now := time.Now()
	day, _ := time.ParseDuration("24h")
	threshold := start.Add(day)
	if now.After(threshold) {
		return green.SprintfFunc()(start.String())
	} else if now.After(start) {
		return yellow.SprintfFunc()(start.String())
	} else {
		return red.SprintfFunc()(start.String())
	}
}

// certEnd takes a given end time for the validity of
// a certificate and returns that time colored properly
// based on how close it is to expiry. If the certificate
// is more than a month away from expiring it returns a
// green string. If the certificate is less than a month
// from expiry it returns a yellow string. If the certificate
// is expired it returns a red string.
func certEnd(end time.Time) string {
	now := time.Now()
	month, _ := time.ParseDuration("720h")
	threshold := now.Add(month)
	if threshold.Before(end) {
		return green.SprintfFunc()(end.String())
	} else if now.Before(end) {
		return yellow.SprintfFunc()(end.String())
	} else {
		return red.SprintfFunc()(end.String())
	}
}

func redify(text string) string {
	return red.SprintfFunc()("%s", text)
}
