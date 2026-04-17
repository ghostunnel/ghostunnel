---
title: ACME Support
description: Automatically obtain and renew public TLS certificates via Let's Encrypt or other ACME certificate authorities.
weight: 30
---

In server mode, Ghostunnel can automatically obtain and renew a public TLS
certificate via the [ACME][acme-rfc] protocol. This is powered by
[certmagic][certmagic], which handles certificate storage, renewal, and OCSP
stapling.

## Basic usage

To enable ACME, use the `--auto-acme-cert` flag with the FQDN to obtain a
certificate for. You must also specify an email address with
`--auto-acme-email` (for CA notifications about certificate lifecycle events)
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
`--auto-acme-testca`. When set, the `--auto-acme-ca` flag is ignored.

## Requirements

ACME is only supported in server mode. Ghostunnel must either be listening on
a public interface on tcp/443, or have tcp/443 forwarded to it (e.g. via a
systemd socket or iptables). Public DNS records must exist for the FQDN that
resolve to the public listening interface IP.

Ghostunnel uses the [TLS-ALPN-01][tls-alpn-01] challenge type (HTTP-01 is
disabled), so port 443 must be reachable.

## Certificate storage and renewal

Certificates are stored locally by certmagic in its default storage directory
(typically `~/.local/share/certmagic` or the equivalent on your OS). Certmagic
automatically renews certificates before they expire, so no manual intervention
or `--timed-reload` is needed for ACME certificates.

If a valid certificate already exists locally, Ghostunnel loads it from cache
on startup without contacting the CA.

## Startup retry behavior

On startup, Ghostunnel attempts to obtain the initial certificate up to 5
times with exponential backoff (starting at 5 seconds, capped at 2 minutes).
If all attempts fail, Ghostunnel exits with an error.

[acme-rfc]: https://datatracker.ietf.org/doc/html/rfc8555
[letsencrypt]: https://letsencrypt.org/
[tls-alpn-01]: https://datatracker.ietf.org/doc/html/rfc8737
[certmagic]: https://pkg.go.dev/github.com/caddyserver/certmagic
