---
title: SPIFFE Workload API
description: Automatically manage certificates and trusted roots via SPIRE or other SPIFFE-compatible workload identity providers.
weight: 60
---

Ghostunnel can obtain certificates and trusted roots from the
[SPIFFE](https://spiffe.io)
[Workload API](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md).
With the Workload API, Ghostunnel maintains up-to-date, frequently rotated
client/server identities (X.509 certificates and private keys) and trusted
X.509 roots. Peers are expected to present SPIFFE
[X509-SVIDs](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md),
which are verified using SPIFFE authentication.

To enable workload API support, use the `--use-workload-api` flag. By default,
the location of the SPIFFE Workload API socket is picked up from the
`SPIFFE_ENDPOINT_SOCKET` environment variable. If you prefer to specify this via
flag, the `--use-workload-api-addr` flag can be used to explicitly set the address.

On UNIX systems (Linux, macOS):

```bash
ghostunnel server \
    --use-workload-api-addr /run/spire/sockets/agent.sock \
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

### Authorization

The identity of the peer, i.e. the [SPIFFE ID](https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md), is embedded as a URI SAN on the
X509-SVID. Accordingly, the existing `--verify-uri` and `--allow-uri`
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

### Trust bundle updates

When using the Workload API, Ghostunnel automatically watches for updates
to both the X.509 identity (certificate and key) and the trusted root CA
bundle. When the SPIFFE provider (e.g. SPIRE) rotates certificates or
updates the trust bundle, Ghostunnel picks up the changes without requiring
a manual reload or restart.

### Demo

See the [end-to-end demo](https://github.com/ghostunnel/ghostunnel/tree/master/docs/spiffe-workload-api-demo) for an example
using Ghostunnel with SPIFFE Workload API support backed by
[SPIRE](https://spiffe.io/spire/).
