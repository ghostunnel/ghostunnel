---
title: Access Control Flags
description: Control which clients or servers are allowed to connect based on certificate fields (CN, OU, DNS/URI SAN) or OPA policies.
weight: 20
aliases:
  - /docs/access-flags/
---

Ghostunnel uses mutual TLS for authentication and access control. Both the
client and server present a certificate that the other party verifies.

## Server mode

Several flags restrict which clients can connect, based on fields in the
client certificate.

When multiple certificate-field flags (`--allow-cn`, `--allow-ou`,
`--allow-dns`, `--allow-uri`) are specified, they are OR'd together: a client is
allowed if at least one flag matches. `--allow-policy`/`--allow-query` may also
be combined with these flags and is OR'd together with them. The remaining flags,
`--allow-all` and `--disable-authentication`, are each mutually exclusive with
the rest.

* `--allow-all`

Allow all clients with a valid certificate, regardless of the certificate
subject. Mutually exclusive with other access control flags.

* `--allow-cn`

Allow clients with the given common name (CN). Can be repeated. Performs an
exact string match.

* `--allow-ou`

Allow clients with the given organizational unit (OU). Can be repeated.
Performs an exact string match.

* `--allow-dns`

Allow clients with the given DNS subject alternative name (DNS SAN). Can be
repeated. Matches the DNS SAN value on the certificate; no DNS lookups are
performed.

* `--allow-uri`

Allow clients with the given URI subject alternative name (URI SAN). Can be
repeated. Supports `*` and `**` wildcards.

For example, setting `--allow-uri=spiffe://ghostunnel/*` would allow clients
with `spiffe://ghostunnel/client1` or `spiffe://ghostunnel/client2` URI SANs (as
well as other values). See documentation for the [wildcard][wildcard] package
for more information.

* `--allow-spki-pin`

Allow clients whose leaf certificate's public key matches the given SPKI pin,
of the form `<algo>:<base64-digest>`, where `<algo>` is one of `sha256`,
`sha384`, or `sha512`, and `<base64-digest>` is the base64 encoding of the
hash of the DER-encoded SubjectPublicKeyInfo (hash construction per
[RFC 7469 §2.4][rfc7469]). Can be repeated to allow multiple keys (e.g. a
current and a backup key for rotation).

This is out-of-band key pinning in the style of [RFC 7858 §4.2][rfc7858]: the
client is authenticated by the pin alone, so the certificate chain, validity
period, and hostname are *not* verified and a pinned key need not chain to a
trusted CA. Mutually exclusive with other access control flags and with
`--use-workload-api`.

When `--allow-spki-pin` is set, `--cacert` has no effect on client
verification: the client is authenticated by the pin alone, and ghostunnel does
not advertise the CA pool in the TLS handshake (so a strict client is not
prompted to withhold a pinned certificate that does not chain to it).

> **Prefer an OPA policy if the client is already PKIX-valid.** `--allow-spki-pin` is
> for clients whose certificate is *not* otherwise trusted (self-signed or
> out-of-band-distributed keys). If clients already present a certificate that
> chains to `--cacert` and you only want to *additionally* restrict to a specific
> key, keep normal chain validation and pin via `--allow-policy` over
> `input.certificate.RawSubjectPublicKeyInfo` (its SHA-256 is the SPKI pin). See
> the Open Policy Agent section below.

* `--allow-policy` and `--allow-query` (*OPA bundle support since v1.9.0*)

Allow clients where a Rego policy evaluates to `true` with the given query.
For more information, see the Open Policy Agent section below.

* `--disable-authentication`

Disable client authentication entirely, no client certificate is required.
Anyone can connect. Mutually exclusive with other access control flags.

### Passing Client Identity to Backends

Ghostunnel verifies client certificates before forwarding connections, but
backends may also need to know the client's identity for their own access
control, logging, or auditing. Use `--proxy-protocol-mode=tls-full` (available
since v1.10.0) to forward the client certificate (CN, full DER-encoded cert) to
the backend via [PROXY protocol v2]({{< ref "proxy-protocol.md" >}}) TLV
extensions.

## Client mode

In client mode, additional flags can verify properties of the server
certificate. Standard hostname verification always runs regardless of which
flags are set; by default it checks the hostname from `--target` against the
server certificate's DNS/IP SANs, but `--override-server-name` (see below) can
redirect verification to a different name (e.g. when dialing by IP, or when
the cert's SAN doesn't match the dialed host). Two flags are exceptions that
replace hostname verification entirely rather than adding to it: the
[SPIFFE Workload API]({{< ref "spiffe-workload-api.md" >}}) (when
`--use-workload-api` is set, hostname verification is replaced by SPIFFE
authentication — peers are verified as presenting a valid X509-SVID, so use
`--verify-uri` to pin the expected SPIFFE ID), and `--verify-spki-pin` (see below,
which authenticates the server by its SPKI pin alone).

When multiple verification flags are specified, they are OR'd together: a
connection is allowed if at least one flag matches (and hostname verification
passes).

* `--override-server-name`

Override the server name used for hostname verification and SNI, instead of
using the hostname from `--target`. Useful when dialing by IP, when the
backend's certificate SAN does not match the dial address, or to pin SNI to a
specific virtual host. Ignored when `--use-workload-api` is in effect. See the
`ServerName` field on [`tls.Config`][tls].

* `--verify-cn`

Verify the common name (CN) of the server certificate, in addition to
hostname verification. Can be repeated. Performs an exact string match.

* `--verify-ou`

Verify the organizational unit (OU) of the server certificate, in addition to
hostname verification. Can be repeated. Performs an exact string match.

* `--verify-dns`

Verify that a DNS subject alternative name (DNS SAN) is present on the server
certificate, in addition to hostname verification. Can be repeated.

* `--verify-uri`

Verify that a URI subject alternative name (URI SAN) is present on the server
certificate, in addition to hostname verification. Supports `*` and `**`
wildcards.

For example, setting `--verify-uri=spiffe://ghostunnel/*` would allow servers
with `spiffe://ghostunnel/server1` or `spiffe://ghostunnel/server2` URI SANs (as
well as other values). See documentation for the [wildcard][wildcard] package
for more information.

* `--verify-spki-pin`

Verify the server's leaf certificate's public key against the given SPKI pin,
of the form `<algo>:<base64-digest>`, where `<algo>` is one of `sha256`,
`sha384`, or `sha512`, and `<base64-digest>` is the base64 encoding of the
hash of the DER-encoded SubjectPublicKeyInfo (hash construction per
[RFC 7469 §2.4][rfc7469]). Can be repeated to accept multiple keys (e.g. a
current and a backup key for rotation).

Unlike the other verification flags, this is out-of-band key pinning in the
style of [RFC 7858 §4.2][rfc7858]: the server is authenticated by the pin
alone, so standard hostname verification, chain validation, and validity-period
checks do *not* run. Mutually exclusive with the other verification flags and
with `--use-workload-api`. It *may*, however, be combined with
`--disable-authentication`: on the client that flag only suppresses sending a
client certificate, so the pair yields a deployment where ghostunnel presents no
certificate of its own and authenticates the server by pin alone — the typical
DNS-over-TLS (DoT) style setup that motivates SPKI pinning.

> **Prefer an OPA policy if the server is already PKIX-valid.** `--verify-spki-pin` is
> for servers whose certificate is *not* otherwise trusted (self-signed or
> out-of-band-distributed keys). If the server already presents a certificate
> that chains to `--cacert` and passes hostname verification, and you only want
> to *additionally* restrict to a specific key, keep normal validation and pin
> via `--verify-policy` over `input.certificate.RawSubjectPublicKeyInfo` (its
> SHA-256 is the SPKI pin). See the Open Policy Agent section below.

* `--verify-policy` and `--verify-query` (*OPA bundle support since v1.9.0*)

Verify that a Rego policy evaluates to `true` with the given query.
For more information, see the Open Policy Agent section below.

* `--disable-authentication`

Disable client authentication, no certificate is sent to the server. Useful
when the backend does not require mutual TLS.

[tls]: https://pkg.go.dev/crypto/tls
[wildcard]: https://pkg.go.dev/github.com/ghostunnel/ghostunnel/wildcard
[rfc7469]: https://www.rfc-editor.org/rfc/rfc7469#section-2.4
[rfc7858]: https://www.rfc-editor.org/rfc/rfc7858#section-4.2

## Open Policy Agent

*Available since v1.7.0, OPA bundle support available since v1.9.0.*

Ghostunnel supports [Open Policy Agent][opa] (OPA) in both server and client
mode. The policy must be an [OPA bundle][opa-bundles] on disk. In server mode,
`--allow-policy`/`--allow-query` may be combined with the other access control
flags and are OR'd together with them; likewise in client mode,
`--verify-policy`/`--verify-query` may be combined with other verification flags.
In both cases we recommend expressing all access control logic in the policy
itself. Policy bundles reload at runtime via `--timed-reload` or `SIGHUP`, just
like certificates.

[opa]: https://www.openpolicyagent.org/
[opa-bundles]: https://www.openpolicyagent.org/docs/latest/management-bundles/

To build a bundle from a `.rego` file, use the `opa build` command:

```bash
opa build policy.rego -o bundle.tar.gz
```

See the [OPA bundle documentation][opa-bundles] for details on bundle
structure and manifest options.

To use it in server mode, specify the `--allow-policy` and `--allow-query` flags.

Example:
```bash
ghostunnel server [...] --allow-policy=bundle.tar.gz --allow-query=data.policy.allow
```

To use it in client mode, specify the `--verify-policy` and `--verify-query` flags.

Example:
```bash
ghostunnel client [...] --verify-policy=bundle.tar.gz --verify-query=data.policy.allow
```

Inside your policy, the peer's X.509 certificate is available as
`input.certificate`. The example below checks whether the client certificate
contains an allowed common name or SPIFFE ID.

You can use the [Rego Playground](https://play.openpolicyagent.org) to test and
develop policies. See the documentation for [x509.Certificate](https://pkg.go.dev/crypto/x509#Certificate)
for the structure of the `input.certificate` variable.

Example ([Playground](https://play.openpolicyagent.org/p/uMcOcUkQPE)):
```rego {file="policy.rego"}
package policy

import input

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
	not uri.Fragment
	not uri.RawFragment

	# Match host/path against the pattern
	glob.match(spiffe_id, [".", "/"], sprintf("%s%s", [uri.Host, uri.Path]))
}
```

The corresponding query for this policy is `data.policy.allow`.

See [x509.Certificate](https://pkg.go.dev/crypto/x509#Certificate) for all
available fields, and the
[Rego documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
for the policy language reference.

### Notes

* Policy bundles must be local files. There is no built-in support for loading
  from a remote OPA server. Fetch and store bundles locally using a separate
  process.
* Passing a raw `.rego` file instead of a bundle to `--allow-policy` or
  `--verify-policy` still works for backward compatibility (treated as V0).
  Using a bundle is recommended so you can set the Rego language version in
  the bundle manifest.
* By OPA convention, a policy is considered "allowed" if the query produces
  exactly one result with a single expression whose value is `true`, and no
  variable bindings.
* Policy evaluation timeout is the same as the connection timeout. If a policy
  takes more time to execute than the specified connection timeout, the connection
  will fail.
