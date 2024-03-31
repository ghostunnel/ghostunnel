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

Allow clients with given organizational unit (OU) field in the subject. Can be
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

* `--allow-policy` and `--allow-query`

Allow clients where a Rego policy evaluates to `true` with the given query.
For more information, see the Open Policy Agent section below.

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
different from the hostname that was passed in `--target`. This also sets the
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

[wildcard]: https://godoc.org/github.com/ghostunnel/ghostunnel/wildcard

* `--verify-policy` and `--verify-query`

Verify that a Rego policy evaluates to `true` with the given query.
For more information, see the Open Policy Agent section below.

* `--disable-authentication`

Disable client authentication, no certificate will be provided to the server.
This is useful if you just want to use Ghostunnel to wrap a connection in TLS
but the backend doesn't require mutual authentication.

[tls]: https://golang.org/pkg/crypto/tls
[wildcard]: https://godoc.org/github.com/ghostunnel/ghostunnel/wildcard

### Open Policy Agent

<span style="color:red">Note: This feature is considered experimental and is
subject to future breaking changes. Please report bugs if you find them!</span>

Ghostunnel has support for Open Policy Agent (OPA), both in server and client
mode. The policy file must be present on disk for Ghostunnel to use it and the
use of OPA is mutually exclusive with any other `allow` (or `verify`) flags.
Policy files can be reloaded at runtime much like certificates, with the
`--timed-reload` flag or via `SIGHUP` on a recent release.

To use it in server mode, specify the `--allow-policy` and `--allow-query` flags.

Example:
```
ghostunnel server [...] --allow-policy=policy.rego --allow-query=data.policy.allow
```

To use it in client mode, specify the `--verify-policy` and `--verify-query` flags.

Example:
```
ghostunnel server [...] --verify-policy=policy.rego --allow-query=data.policy.allow
```

Inside your policy, you can access the reflected X.509 peer certificate using
`input.certificate`. For example, the policy below verifies that the presented
client certificate contains at least one of the allowed common names or SPIFFE
IDs.

You can use the [Rego Playground](https://play.openpolicyagent.org) to test and
develop policies. See the documentation for [x509.Certificate](https://pkg.go.dev/crypto/x509#Certificate) 
for the structure of the `input.certificate` variable.

Example ([Playground](https://play.openpolicyagent.org/p/uMcOcUkQPE)):
```rego
package policy

import input

import future.keywords.if
import future.keywords.in

default allow := false

allowed_common_names = [
	"client1",
	"client2",
]

allowed_spiffe_ids = [
	"example.com/client1",
	"example.com/client1/*",
	"example.com/client2",
	"example.com/client2/*",
]

allow if {
	# Allow if common name matches a pattern in allowed_common_names
	some common_name in allowed_common_names
	glob.match(common_name, [], input.certificate.Subject.CommonName)
}

allow if {
	# Allow if one of the URI SANs matches a pattern in allowed_spiffe_ids
	some uri in input.certificate.URIs
	some spiffe_id in allowed_spiffe_ids

	# Basic sanity checks for the URI SAN before we compare
	uri.Scheme == "spiffe"

	# User, query, fragment, etc. should not be set in the URI SAN
	not uri.User
	not uri.Opaque
	not uri.RawQuery
	not uri.Fragement
	not uri.RawFragment

	# Match host/path against the pattern
	glob.match(spiffe_id, [".", "/"], sprintf("%s%s", [uri.Host, uri.Path]))
}
```

The corresponding query for this policy is `data.policy.allow`, because we
want to determine the outcome of the policy by looking at `allow`.

See the documentation about [Golang's x509.Certificate
struct](https://pkg.go.dev/crypto/x509#Certificate) for more about other
properties you can match on, and the [Rego
documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
for more about the policy language.

#### Caveats

* There is no mechanism to load a policy from a remote OPA server. The policy
  file has to be local, or be retrieved and stored locally out of band by a
  different process.
* By standard OPA convention, we consider a policy to be "allowed" if the query
  is exactly one result with exactly one element that has the value `true`.
* Policy evaluation timeout is the same as the connection timeout. If a policy
  takes more time to execute than the specified connection timeout, the connection
  will fail.
