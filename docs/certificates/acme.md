---
title: ACME Support
description: Automatically obtain and renew public TLS certificates via Let's Encrypt or other ACME certificate authorities.
weight: 20
aliases:
  - /docs/acme/
---

In server mode, Ghostunnel can automatically obtain and renew a public TLS
certificate via the [ACME][acme-rfc] protocol. This is powered by
[certmagic][certmagic], which handles certificate storage, renewal, and OCSP
stapling.

## Basic Usage

To enable ACME, use the `--auto-acme-cert` flag with the FQDN to obtain a
certificate for. You must also specify an email address with
`--auto-acme-email` (used by the CA for expiration and renewal notices)
and agree to the CA's Terms of Service with `--auto-acme-agree-to-tos`:

```bash
ghostunnel server \
    --auto-acme-cert=myservice.example.com \
    --auto-acme-email=admin@example.com \
    --auto-acme-agree-to-tos \
    --listen 0.0.0.0:443 \
    --target localhost:8080 \
    --allow-cn client
```

Ghostunnel defaults to using [Let's Encrypt][letsencrypt] as the ACME CA. You
can specify a different ACME CA URL using `--auto-acme-ca`. To test against a
non-production CA (e.g. Let's Encrypt's staging environment), use
`--auto-acme-testca=URL` with the staging CA's directory URL (e.g.
`--auto-acme-testca=https://acme-staging-v02.api.letsencrypt.org/directory`).
When set, the `--auto-acme-ca` flag is ignored.

## Requirements

ACME is only supported in server mode. Ghostunnel must either be listening on
a public interface on tcp/443, or have tcp/443 forwarded to it (e.g. via a
systemd socket or iptables). Public DNS records must exist for the FQDN that
resolve to the public listening interface IP.

Ghostunnel uses the [TLS-ALPN-01][tls-alpn-01] challenge type (HTTP-01 is
disabled), so port 443 must be reachable.

## Certificate Storage and Renewal

Certmagic stores certificates and account keys on disk. The default location
depends on your OS:

| OS | Default path |
|----|-------------|
| Linux / macOS | `~/.local/share/certmagic` (or `$XDG_DATA_HOME/certmagic`) |
| Windows | `%USERPROFILE%\.local\share\certmagic` (certmagic resolves the home directory from `HOME` or `HOMEDRIVE`+`HOMEPATH` first, falling back to `USERPROFILE`) |

Certmagic automatically renews certificates before they expire, so no manual
intervention or `--timed-reload` is needed for ACME certificates.

If a valid certificate already exists locally, Ghostunnel loads it from cache
on startup without contacting the CA.

## Renewal Under mTLS

Renewal works even when client certificate authentication is enabled with
flags like `--allow-cn`, `--allow-ou`, or `--allow-dns`. To check that
you control the domain, the ACME CA opens a TLS handshake to port 443 that
advertises the `acme-tls/1` ALPN protocol and presents no client cert.
Ghostunnel lets that one handshake complete without requiring a client cert.
Every other connection still needs a valid client cert as configured.

Several rules keep this exemption from turning into a way around mTLS:

- The ClientHello must offer exactly `["acme-tls/1"]` as its ALPN list. A
  client that offers `acme-tls/1` alongside another protocol such as `h2`
  is treated as a normal client and must present a valid client cert.
- The ClientHello must include a (non-empty) SNI server name, since the
  TLS-ALPN-01 challenge certificate is selected by SNI. A client offering
  `acme-tls/1` without SNI is treated as a normal client.
- The relaxed handshake pins ALPN to `acme-tls/1` and cannot fall back to a
  different protocol. TLS session resumption is also disabled for the relaxed
  handshake, so a ticket issued during a renewal probe cannot be reused later
  by a real client to skip mTLS.
- After the handshake finishes, Ghostunnel checks which ALPN was
  negotiated. Any connection on `acme-tls/1` is closed without dialing the
  backend. The validator only reads the challenge certificate from the
  handshake and never sends application data.

There are no flags to configure this. It is always on when ACME is enabled.

## Revoking or Force-Renewing

Certmagic handles renewal automatically, but if you need to force a renewal
(e.g. after a key compromise), delete the certificate and key files from the
certmagic storage directory and restart Ghostunnel. It will obtain a fresh
certificate on startup.

To revoke a certificate with Let's Encrypt directly, use the
[certbot revoke][certbot-revoke] command or the ACME revocation endpoint
described in [RFC 8555 Section 7.6][acme-revoke].

[certbot-revoke]: https://eff-certbot.readthedocs.io/en/latest/using.html#revoking-certificates
[acme-revoke]: https://datatracker.ietf.org/doc/html/rfc8555#section-7.6

## Startup Retry Behavior

On startup, Ghostunnel attempts to obtain the initial certificate up to 5
times with exponential backoff (starting at 5 seconds, capped at 2 minutes).
If all attempts fail, Ghostunnel exits with an error.

[acme-rfc]: https://datatracker.ietf.org/doc/html/rfc8555
[letsencrypt]: https://letsencrypt.org/
[tls-alpn-01]: https://datatracker.ietf.org/doc/html/rfc8737
[certmagic]: https://pkg.go.dev/github.com/caddyserver/certmagic
