Access Control Flags
====================

Ghostunnel uses TLS with mutual authentication for authentication and access
control. This means that both the client and server present a certificate that
can be verified by the other party. 

### Server mode

There are several flags available to restrict which clients can connect to a
Ghostunnel server, based on checks on the subject of the client certificate. 

Access control flags in server mode are treated as a logical disjunction (OR) 
when multiple flags are specified. This means that a client will be allowed to
complete a connection as long as at least one flag matches.

* `--allow-all`

Setting this flag allows all clients with a valid certificate, regardless of
the client certificate subject. This flag is mutually exclusive with other
access control flags.

* `--allow-cn`

Allow clients with given common name (CN) in the subject. Can be repeated to
allow multiple clients with different CNs to connect. Performs an exact string
comparison on the CN field.

* `--allow-ou`

Allow clients with given organizational unit (CN) field in the subject. Can be
repeated to allow multiple clients with different OUs to connect. Performs an
exact string comparison on the OU field.

* `--allow-dns`

Allow clients with given DNS subject alternative name (DNS SAN) in the subject.
Can be repeated to allow multiple clients with different DNS SANs to connect.
Note that this performs the access check based on a comparison of the the DNS
SAN value of the client certificate, it does not perform any DNS lookups.

* `--allow-uri`

Allow clients with given URI subject alternative name (URI SAN) in the subject.
Can be repeated to allow multiple clients with different URI SANs to connect.
This flag may also contain `*` and `** `wildcards that can be used to match
multiple clients.

For example, setting `--allow-uri=spiffe://ghostunnel/*` would allow clients
with `spiffe://ghostunnel/client1` or `spiffe://ghostunnel/client2` URI SANs (as
well as other values). See documentation for the [wildcard][wildcard] package
for more information.

* `--disable-authentication`

Disables client authentication entirely, no client certificate will be required
from any client. This means that anyone will be able to establish a connection
to the Ghostunnel server. This flag is mutually exclusive with other access
control flags.

### Client mode

Ghostunnel in client mode offers various flags that can be used to augment and
perform additional checks on servers it connects to. Regardless of flags passed
to the client, it will always perform standard hostname verification to check
the hostname against the server certificate.

Access control flags in client mode are treated as a logical disjunction (OR) 
when multiple flags are specified. This means that a client will be allowed to
complete a connection as long as at least one flag matches, assuming that
hostname verification was also successful.

* `--override-server-name`

If set, overrides the server name used for hostname verification to be
different from the hostname that was passed in `--listen`. This also sets the
hostname passed to the backend for SNI purposes. The logic for hostname
verification is implemented as part of the [crypto/tls][tls] package in Go's
standard library, see the `ServerName` field on the `tls.Config` struct.

* `--verify-cn`

Verify the common name (CN) of the server certificate, on top of the hostname.
Can be repeated to check that at least one of a set of CNs is present. This
performs an exact string comparison on the CN field of the certificate.

* `--verify-ou`

Verify the organizational unit (OU) of the server certificate, on top of the
hostname. Can be repeated to check that at least one of a set of OUs is
present. This performs an exact string comparison on the OU field of the
certificate.

* `--verify-dns`

Verify the presence of a DNS subject alternative name (DNS SAN) on the server
certificate, on top of the hostname. This checks that the given DNS name is
listed as a valid name on the certificate. Can be repeated to require
that at least one of a set of hostnames is present.

* `--verify-uri`

Verify the presence of a URI subject alternative name (URI SAN) on the server
certificate, on top of the hostname. This checks that the given URI name is
listed as a valid name on the certificate. This flag may also contain `*` and
`** `wildcards that can be used to match multiple servers.

For example, setting `--verify-uri=spiffe://ghostunnel/*` would allow servers
with `spiffe://ghostunnel/server1` or `spiffe://ghostunnel/server2` URI SANs (as
well as other values). See documentation for the [wildcard][wildcard] package
for more information.

[wildcard]: https://godoc.org/github.com/square/ghostunnel/wildcard

* `--disable-authentication`

Disable client authentication, no certificate will be provided to the server.
This is useful if you just want to use Ghostunnel to wrap a connection in TLS
but the backend doesn't require mutual authentication.

[tls]: https://golang.org/pkg/crypto/tls
[wildcard]: https://godoc.org/github.com/square/ghostunnel/wildcard
