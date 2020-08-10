// Command ghostunnel implements a simple SSL/TLS proxy with mutual
// authentication for securing non-TLS services. Ghostunnel in server mode
// runs in front of a backend server and accepts TLS-secured connections, which
// are then proxied to the (insecure) backend. A backend can be a TCP
// domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
// (insecure) connections through a TCP or UNIX domain socket and proxies them
// to a TLS-secured service.
package main

import (
	"os"

	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var manPageTemplate = `{{define "FormatFlags"}}\
{{range .Flags}}\
{{if not .Hidden}}\
.TP
\fB{{if .Short}}-{{.Short|Char}}, {{end}}--{{.Name}}{{if not .IsBoolFlag}}={{.FormatPlaceHolder}}{{end}}\\fR
{{.Help}}
{{end}}\
{{end}}\
{{end}}\
{{define "FormatCommand"}}\
{{if .FlagSummary}} {{.FlagSummary}}{{end}}\
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}{{if .Default}}*{{end}}>{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}\
{{end}}\
{{define "FormatCommands"}}\
{{range .FlattenedCommands}}\
{{if not .Hidden}}\
.SS
\fB{{.FullCommand}}{{template "FormatCommand" .}}\\fR
.PP
{{.Help}}
{{template "FormatFlags" .}}\
{{end}}\
{{end}}\
{{end}}\
{{define "FormatUsage"}}\
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}\\fR
{{end}}\
.TH {{.App.Name}} 1 {{.App.Version}} "{{.App.Author}}"
.SH "NAME"
{{.App.Name}}
.SH "SYNOPSIS"
.TP
\fB{{.App.Name}}{{template "FormatUsage" .App}}
.SH "DESCRIPTION"
{{.App.Help}}

Ghostunnel supports two modes, client mode and server mode. Ghostunnel in
server mode runs in front of a backend server and accepts TLS-secured
connections, which are then proxied to the (insecure) backend. A backend can be
a TCP domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
(insecure) connections through a TCP or UNIX domain socket and proxies them to
a TLS-secured service.

For a more in-depth explanation, please see the README.md file (and docs
folder) that shipped with ghostunnel or view the latest docs on
github.com/ghostunnel/ghostunnel.
.SH "CERTIFICATES & PRIVATE KEYS"
Ghostunnel accepts certificates in multiple different file formats.

The \fB--keystore\fR flag can take a PKCS#12 keystore or a combined PEM file
with the certificate chain and private key as input (format is auto-detected).
The \fB--cert\fR and \fB--key\fR flags can be used to load a certificate chain
and key from separate PEM files (instead of a combined one).

Ghostunnel also supports loading identities from the macOS keychain and having
private keys backed by PKCS#11 modules, see the documentation on GitHub for
examples.
.SH "EXAMPLE: SERVER MODE"
Start a ghostunnel in server mode to proxy connections from localhost:8443
to localhost:8080, while only allowing connections from client certificates
with CN=client:

    ghostunnel server \\
        --listen localhost:8443 \\
        --target localhost:8080 \\
        --keystore server-keystore.p12 \\
        --cacert cacert.pem \\
        --allow-cn client

To set allowed clients, you must specify at least one of \fB--allow-all\fR,
\fB--allow-cn\fR, \fB--allow-ou\fR, \fB--allow-dns\fR or \fB--allow-uri\fR. All
checks are made against the certificate of the client. Multiple flags are
treated as a logical disjunction (OR), meaning clients can connect as long as
any of the flags match. To disable requiring client certificates, use
\fB--disable-authentication\fR.
.SH "EXAMPLE: CLIENT MODE"
Start a ghostunnel in client mode to proxy connections from localhost:8080
to localhost:8443, doing only hostname verification to validate the server
certificate:

    ghostunnel client \\
        --listen localhost:8080 \\
        --target localhost:8443 \\
        --cert client-cert.pem \\
        --key client-key.pem \\
        --cacert cacert.pem

Use \fB--override-server-name\fR to overrides the server name used for hostname
verification. Various access control flags exist to perform additional
verification (on top of the regular hostname verification) of server
certificates, such as \fB--verify-cn\fR, \fB--verify-ou\fR, \fB--verify-dns\fR
and \fB--verify-uri\fR. Multiple flags are treated as a logical disjunction
(OR), meaning clients will connect to the server as long as any of the flags
match, assuming that hostname verification was also successful. To disable
sending client certificates, use \fB--disable-authentication\fR.
.SH "OPTIONS"
{{template "FormatFlags" .App}}\
{{if .App.Commands}}\
.SH "COMMANDS"
{{template "FormatCommands" .App}}\
{{end}}\
`

func generateManPage(c *kingpin.ParseContext) (err error) {
	app.Writer(os.Stdout)
	if err := app.UsageForContextWithTemplate(c, 2, manPageTemplate); err != nil {
		return err
	}
	exitFunc(0)
	return
}
