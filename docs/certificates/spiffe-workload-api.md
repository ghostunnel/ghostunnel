---
title: SPIFFE Workload API
description: Automatically manage certificates and trusted roots via SPIRE or other SPIFFE-compatible workload identity providers.
weight: 30
aliases:
  - /docs/spiffe-workload-api/
---

Ghostunnel can obtain certificates and trusted roots from the
[SPIFFE](https://spiffe.io)
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
With the Workload API, Ghostunnel maintains up-to-date, frequently rotated
client/server identities (X.509 certificates and private keys) and trusted
X.509 roots. Peers are expected to present SPIFFE
[X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md),
which are verified using SPIFFE authentication.

To enable workload API support, set the `SPIFFE_ENDPOINT_SOCKET` environment
variable or pass the `--use-workload-api-addr` flag. Either of these implicitly
enables `--use-workload-api`, so the explicit flag is not required when the
address is provided. You can also pass `--use-workload-api` on its own if the
environment variable is already set.

On UNIX systems (Linux, macOS):

```bash
ghostunnel server \
    --use-workload-api-addr unix:///run/spire/sockets/agent.sock \
    --listen localhost:8443 \
    --target localhost:8080 \
    --allow-uri spiffe://domain.test/frontend
```

On Windows:

```bash
ghostunnel server \
    --use-workload-api-addr npipe:spire-agent\\public\\api \
    --listen localhost:8443 \
    --target localhost:8080 \
    --allow-uri spiffe://domain.test/frontend
```

## Authorization

The identity of the peer, i.e. the
[SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md),
is embedded as a URI SAN on the X509-SVID. Accordingly, the existing `--verify-uri` and `--allow-uri`
flags can be used to authorize the peer:

As a server:

```bash
ghostunnel server \
    --use-workload-api \
    --listen localhost:8443 \
    --target localhost:8080 \
    --allow-uri spiffe://domain.test/frontend
```

As a client:

```bash
ghostunnel client \
    --use-workload-api \
    --listen localhost:8080 \
    --target localhost:8443 \
    --verify-uri spiffe://domain.test/backend
```

## Trust Bundle Updates

When using the Workload API, Ghostunnel automatically watches for updates
to both the X.509 identity (certificate and key) and the trusted root CA
bundle. When the SPIFFE provider (e.g. SPIRE) rotates certificates or
updates the trust bundle, Ghostunnel picks up the changes without requiring
a manual reload or restart.

## Demo

See the [end-to-end demo](https://github.com/ghostunnel/ghostunnel/tree/master/docs/spiffe-workload-api-demo) for an example
using Ghostunnel with SPIFFE Workload API support backed by
[SPIRE](https://spiffe.io/spire/). The [SPIRE getting started guide][spire-getting-started] covers setting up
SPIRE from scratch on Linux/macOS.

[spire-getting-started]: https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/
