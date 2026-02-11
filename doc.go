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

	kingpin "github.com/alecthomas/kingpin/v2"
)

var manPageTemplate = `{{define "FormatFlags"}}\
{{range .Flags}}\
{{if not .Hidden}}\
\fB{{if .Short}}-{{.Short|Char}}, {{end}}--{{.Name}}{{if not .IsBoolFlag}}={{.FormatPlaceHolder}}{{end}}\fR
{{.Help}}
.PP
{{end}}\
{{end}}\
{{end}}\
{{define "FormatCommand"}}\
{{if .FlagSummary}} {{.FlagSummary}}{{end}}\
{{range .Args}} {{if not .Required}}[{{end}}<{{.Name}}{{if .Default}}*{{end}}>{{if .Value|IsCumulative}}...{{end}}{{if not .Required}}]{{end}}{{end}}\
{{end}}\
{{define "FormatCommands"}}\
{{range .FlattenedCommands}}\
{{if not .Hidden}}
.SS
\fB{{.FullCommand}}{{template "FormatCommand" .}}\fR
.PP
{{.Help}}
{{template "FormatFlags" .}}\
{{end}}\
{{end}}\
{{end}}\
{{define "FormatUsage"}}\
{{template "FormatCommand" .}}{{if .Commands}} <command> [<args> ...]{{end}}\fR
{{end}}
.TH {{.App.Name}} 1 {{.App.Version}} "{{.App.Author}}"
.SH "NAME"
{{.App.Name}}
.SH "SYNOPSIS"
\fB{{.App.Name}}{{template "FormatUsage" .App}}\fR
.TP

.SH "DESCRIPTION"
{{.App.Help}}

Ghostunnel supports two modes, client mode and server mode. Ghostunnel in
server mode runs in front of a backend server and accepts TLS-secured
connections, which are then proxied to the (insecure) backend. A backend can be
a TCP domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
(insecure) connections through a TCP or UNIX domain socket and proxies them to
a TLS-secured service.

For a more in-depth explanation, please see the README.md file (and docs
folder) that shipped with Ghostunnel or view the latest docs on
github.com/ghostunnel/ghostunnel.
.SH "CERTIFICATES & PRIVATE KEYS"
Ghostunnel supports multiple methods for loading certificates and private keys.

File-based formats:
.RS
The \fB--keystore\fR flag can take a PKCS#12 keystore or a combined PEM file
with the certificate chain and private key as input (format is auto-detected).
The \fB--cert\fR and \fB--key\fR flags can be used to load a certificate chain
and key from separate PEM files (instead of a combined one).
.RE

SPIFFE Workload API:
.RS
Ghostunnel can retrieve certificates and root CAs from the SPIFFE Workload API
using the \fB--use-workload-api\fR flag. This enables automatic certificate
rotation and is useful in service mesh deployments. The Workload API socket
location can be specified via the \fBSPIFFE_ENDPOINT_SOCKET\fR environment
variable or the \fB--use-workload-api-addr\fR flag.
.RE

ACME (Automatic Certificate Management):
.RS
In server mode, Ghostunnel can automatically obtain and renew public TLS
certificates using the ACME protocol (e.g., Let's Encrypt). Use
\fB--auto-acme-cert\fR with \fB--auto-acme-email\fR and
\fB--auto-acme-agree-to-tos\fR. This requires Ghostunnel to be accessible on
a public interface (tcp/443) with valid DNS records. The ACME CA URL can be
specified with \fB--auto-acme-ca\fR (defaults to Let's Encrypt).
.RE

PKCS#11 (Hardware Security Modules):
.RS
Private keys can be stored in PKCS#11-compatible hardware security modules
(HSMs). Use \fB--cert\fR to specify the certificate chain file, and
\fB--pkcs11-module\fR, \fB--pkcs11-token-label\fR, and \fB--pkcs11-pin\fR to
configure the HSM. PKCS#11 options can also be set via environment variables
(\fBPKCS11_MODULE\fR, \fBPKCS11_TOKEN_LABEL\fR, \fBPKCS11_PIN\fR).
.RE

Keychain (macOS/Windows):
.RS
On macOS and Windows, Ghostunnel can load certificates from the system keychain
using \fB--keychain-identity\fR (by subject CN/serial) or \fB--keychain-issuer\fR
(by issuer CN). On macOS, \fB--keychain-require-token\fR can be used to
require certificates from physical tokens (e.g., Touch ID MacBooks).
.RE

.SH "EXAMPLE: SERVER MODE"
Start a ghostunnel in server mode to proxy connections from localhost:8443
to localhost:8080, while only allowing connections from client certificates
with CN=client:

.nf
    ghostunnel server \\
        --listen localhost:8443 \\
        --target localhost:8080 \\
        --keystore server-keystore.p12 \\
        --cacert cacert.pem \\
        --allow-cn client
.fi

To set allowed clients, you must specify at least one of \fB--allow-all\fR,
\fB--allow-cn\fR, \fB--allow-ou\fR, \fB--allow-dns\fR, \fB--allow-uri\fR, or
\fB--allow-policy\fR. All checks are made against the certificate of the client.
Multiple flags are treated as a logical disjunction (OR), meaning clients can
connect as long as any of the flags match. To disable requiring client
certificates, use \fB--disable-authentication\fR.

.SH "EXAMPLE: CLIENT MODE"
Start a ghostunnel in client mode to proxy connections from localhost:8080
to localhost:8443, doing only hostname verification to validate the server
certificate:

.nf
    ghostunnel client \\
        --listen localhost:8080 \\
        --target localhost:8443 \\
        --cert client-cert.pem \\
        --key client-key.pem \\
        --cacert cacert.pem
.fi

Use \fB--override-server-name\fR to override the server name used for hostname
verification. Various access control flags exist to perform additional
verification (on top of the regular hostname verification) of server
certificates, such as \fB--verify-cn\fR, \fB--verify-ou\fR, \fB--verify-dns\fR,
\fB--verify-uri\fR, or \fB--verify-policy\fR. Multiple flags are treated as a
logical disjunction (OR), meaning clients will connect to the server as long as
any of the flags match, assuming that hostname verification was also successful.
To disable sending client certificates, use \fB--disable-authentication\fR.

.SH "EXAMPLE: UNIX SOCKETS"
Ghostunnel supports UNIX domain sockets for both listening and forwarding:

.nf
# Server mode with UNIX socket
ghostunnel server \\
    --listen unix:/var/run/ghostunnel.sock \\
    --target unix:/var/run/backend.sock \\
    --keystore server-keystore.p12 \\
    --cacert cacert.pem \\
    --allow-cn client

# Client mode with UNIX socket listener
ghostunnel client \\
    --listen unix:/var/run/client.sock \\
    --target localhost:8443 \\
    --keystore client-keystore.p12 \\
    --cacert cacert.pem
.fi

UNIX sockets provide secure local communication without network exposure.

.SH "EXAMPLE: STATUS AND METRICS"
Enable status and metrics endpoints for monitoring and health checks:

.nf
ghostunnel server \\
    --listen localhost:8443 \\
    --target localhost:8080 \\
    --keystore server-keystore.p12 \\
    --cacert cacert.pem \\
    --allow-cn client \\
    --status localhost:6060
.fi

Access status and metrics:
.nf
# Status information (JSON)
curl --cacert cacert.pem https://localhost:6060/_status

# Metrics (Prometheus format)
curl --cacert cacert.pem https://localhost:6060/_metrics/prometheus

# Metrics (JSON format)
curl --cacert cacert.pem https://localhost:6060/_metrics/json
.fi

The status port can also use HTTP by prefixing with "http://" (e.g.,
\fB--status http://localhost:6060\fR). Profiling endpoints can be enabled
with \fB--enable-pprof\fR.

.SH "EXAMPLE: MULTIPLE ACCESS CONTROL FLAGS"
Multiple access control flags can be combined using OR logic:

.nf
ghostunnel server \\
    --listen localhost:8443 \\
    --target localhost:8080 \\
    --keystore server-keystore.p12 \\
    --cacert cacert.pem \\
    --allow-cn client1 \\
    --allow-cn client2 \\
    --allow-ou developers \\
    --allow-uri spiffe://example.com/*
.fi

Clients matching any of the specified criteria (CN=client1 or CN=client2 or
OU=developers or URI matching spiffe://example.com/*) will be allowed to
connect. The same OR logic applies to client mode verification flags
(\fB--verify-cn\fR, \fB--verify-ou\fR, \fB--verify-dns\fR, \fB--verify-uri\fR).

.SH "OPTIONS"
{{template "FormatFlags" .App}}\
{{if .App.Commands}}
.SH "COMMANDS"
{{template "FormatCommands" .App}}\
{{end}}\
`

func generateManPage(c *kingpin.ParseContext) error {
	app.Writer(os.Stdout)
	err := app.UsageForContextWithTemplate(c, 2, manPageTemplate)
	panicOnError(err)
	exitFunc(0)
	return err
}
