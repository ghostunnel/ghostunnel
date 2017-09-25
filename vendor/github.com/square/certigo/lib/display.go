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

	"crypto/x509/pkix"

	"github.com/Masterminds/sprig"
	"github.com/fatih/color"
)

var verboseLayout = `
{{- define "PkixName" -}}
{{- range .Names}}
	{{ .Type | oidName }}: {{ .Value }}
{{- end -}}
{{end -}}

{{- if .Alias}}{{.Alias}}
{{end}}Serial: {{.SerialNumber}}
Valid: {{.NotBefore | certStart}} to {{.NotAfter | certEnd}}
Signature: {{.SignatureAlgorithm | highlightAlgorithm}}{{if .IsSelfSigned}} (self-signed){{end}}
Subject Info:
	{{- template "PkixName" .Subject.Name}}
Issuer Info:
	{{- template "PkixName" .Issuer.Name}}
{{- if .Subject.KeyID}}
Subject Key ID: {{.Subject.KeyID | hexify}}
{{- end}}
{{- if .Issuer.KeyID}}
Authority Key ID: {{.Issuer.KeyID | hexify}}
{{- end}}
{{- if .BasicConstraints}}
Basic Constraints: CA:{{.BasicConstraints.IsCA}}{{if .BasicConstraints.MaxPathLen}}, pathlen:{{.BasicConstraints.MaxPathLen}}{{end}}{{end}}
{{- if .NameConstraints}}
DNS Name Constraints{{if .NameConstraints.Critical}} (critical){{end}}: 
{{- if .NameConstraints.PermittedDNSDomains}}
Permitted:
	{{wrapWith .Width "\n\t" (join ", " .NameConstraints.PermittedDNSDomains)}}
{{- end}}
{{- if .NameConstraints.ExcludedDNSDomains}}
Excluded:
	{{wrapWith .Width "\n\t" (join ", " .NameConstraints.ExcludedDNSDomains)}}
{{- end}}
{{- end}}
{{- if .OCSPServer}}
OCSP Server(s):
	{{wrapWith .Width "\n\t" (join ", " .OCSPServer)}}
{{- end}}
{{- if .IssuingCertificateURL}}
Issuing Certificate URL(s):
	{{wrapWith .Width "\n\t" (join ", " .IssuingCertificateURL)}}
{{- end}}
{{- if .KeyUsage}}
Key Usage:
{{- range .KeyUsage | keyUsage}}
	{{.}}
{{- end}}
{{- end}}
{{- if .ExtKeyUsage}}
Extended Key Usage:
{{- range .ExtKeyUsage}}
	{{. | extKeyUsage}}{{end}}
{{- end}}
{{- if .AltDNSNames}}
DNS Names:
	{{wrapWith .Width "\n\t" (join ", " .AltDNSNames)}}
{{- end}}
{{- if .AltIPAddresses}}
IP Addresses:
	{{wrapWith .Width "\n\t" (join ", " .AltIPAddresses)}}
{{- end}}
{{- if .URINames}}
URI Names:
	{{wrapWith .Width "\n\t" (join ", " .URINames)}}
{{- end}}
{{- if .EmailAddresses}}
Email Addresses:
	{{wrapWith .Width "\n\t" (join ", " .EmailAddresses)}}
{{- end}}
{{- if .Warnings}}
Warnings:
{{- range .Warnings}}
	{{. | redify}}
{{- end}}
{{- end}}`

var layout = `
{{- if .Alias}}{{.Alias}}
{{end -}}
Valid: {{.NotBefore | certStart}} to {{.NotAfter | certEnd}}
Subject: {{.Subject.Name | printShortName }}
Issuer: {{.Issuer.Name | printShortName }}
{{- if .NameConstraints}}
Name Constraints{{if .PermittedDNSDomains.Critical}} (critical){{end}}: {{range .NameConstraints.PermittedDNSDomains}}
	{{.}}{{end}}{{end}}
{{- if .AltDNSNames}}
DNS Names:
	{{wrapWith .Width "\n\t" (join ", " .AltDNSNames)}}{{end}}
{{- if .AltIPAddresses}}
IP Addresses:
	{{wrapWith .Width "\n\t" (join ", " .AltIPAddresses)}}{{end}}
{{- if .URINames}}
URI Names:
	{{wrapWith .Width "\n\t" (join ", " .URINames)}}{{end}}
{{- if .EmailAddresses}}
Email Addresses:
	{{wrapWith .Width "\n\t" (join ", " .EmailAddresses)}}{{end}}
{{- if .Warnings}}
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
func EncodeX509ToText(cert *x509.Certificate, terminalWidth int, verbose bool) []byte {
	c := createSimpleCertificate("", cert)
	c.Width = terminalWidth - 8 /* Need some margin for tab */

	return displayCert(c, verbose)
}

// displayCert takes in a parsed certificate object
// (for jceks certs, blank otherwise), and prints out relevant
// information. Start and end dates are colored based on whether or not
// the certificate is expired, not expired, or close to expiring.
func displayCert(cert simpleCertificate, verbose bool) []byte {
	// Use template functions from sprig, but add some extras
	funcMap := sprig.TxtFuncMap()

	extras := template.FuncMap{
		"certStart":          certStart,
		"certEnd":            certEnd,
		"redify":             redify,
		"highlightAlgorithm": highlightAlgorithm,
		"hexify":             hexify,
		"keyUsage":           keyUsage,
		"extKeyUsage":        extKeyUsage,
		"oidName":            oidName,
		"oidShort":           oidShort,
		"printShortName":     PrintShortName,
	}
	for k, v := range extras {
		funcMap[k] = v
	}

	t := template.New("Cert template").Funcs(funcMap)
	var err error
	if verbose {
		t, err = t.Parse(verboseLayout)
	} else {
		t, err = t.Parse(layout)
	}
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

// timeString formats a time in UTC with minute precision, in the given color.
func timeString(t time.Time, c *color.Color) string {
	return c.SprintfFunc()(t.Format("2006-01-02 15:04 MST"))
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
		return timeString(start, green)
	} else if now.After(start) {
		return timeString(start, yellow)
	} else {
		return timeString(start, red)
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
		return timeString(end, green)
	} else if now.Before(end) {
		return timeString(end, yellow)
	} else {
		return timeString(end, red)
	}
}

func redify(text string) string {
	return red.SprintfFunc()("%s", text)
}

func greenify(text string) string {
	return green.SprintfFunc()("%s", text)
}

// PrintShortName turns a pkix.Name into a string of RDN tuples.
func PrintShortName(name pkix.Name) (out string) {
	// Try to print CN for short name if present.
	if name.CommonName != "" {
		return fmt.Sprintf("CN=%s", name.CommonName)
	}

	// If both CN is missing, just print O, OU, etc.
	printed := false
	for _, name := range name.Names {
		short := oidShort(name.Type)
		if short != "" {
			if printed {
				out += ", "
			}
			out += fmt.Sprintf("%s=%v", short, name.Value)
			printed = true
		}
	}

	return
}
