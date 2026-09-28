---
title: Outbound Proxies
description: Reach the target through an HTTP CONNECT, HTTPS CONNECT, or SOCKS5 proxy in client mode, including client certificate authentication to the proxy.
weight: 20
since: v1.11.4
---

In client mode, Ghostunnel normally opens a direct TCP connection to
`--target`. When the target is only reachable through a proxy, pass
`--proxy URL` and Ghostunnel establishes the TLS session to the target
through that proxy instead. The session is still end-to-end between
Ghostunnel and the target: the proxy only forwards bytes and cannot inspect
or modify the tunneled traffic.

## Supported Proxy Types

| Scheme | Connection to proxy | Notes |
|--------|---------------------|-------|
| `http://host:port` | Plaintext | HTTP `CONNECT` tunnel. Port defaults to `8080`. |
| `https://host:port` | TLS | HTTP `CONNECT` tunnel over TLS. Port defaults to `443`. Supports client certificate authentication to the proxy (see below). |
| `socks5://host:port` | Plaintext | SOCKS5 tunnel. |

```bash
ghostunnel client \
    --listen localhost:8080 \
    --target backend.internal:8443 \
    --keystore client.p12 \
    --cacert cacert.pem \
    --proxy http://proxy.example.com:3128
```

Since the target only needs to be resolvable by the proxy, Ghostunnel skips
resolving `--target` on startup whenever `--proxy` is set, as if
`--skip-resolve` were given. Hostname verification of the target still uses
the hostname from `--target` (or `--override-server-name`).

## HTTPS Proxies

With an `https://` proxy URL, Ghostunnel first performs a TLS handshake with
the proxy and then sends the `CONNECT` request inside that session. The
proxy's certificate is verified against `--proxy-cacert`, or against
`--cacert` when `--proxy-cacert` is not set, using the hostname from the
proxy URL. Set `--proxy-cacert` when the proxy and the target are issued by
different CAs, for example a proxy with a publicly trusted certificate in
front of a private PKI.

### Authenticating to the Proxy

Proxies that require client certificates, such as identity-aware proxies
that grant access based on a short-lived per-user certificate, can be given
their own credential. It is independent of the `--keystore` or
`--cert`/`--key` credential presented to the target.

| Flag | Description |
|------|-------------|
| `--proxy-keystore PATH` | Keystore with the proxy client certificate and key (combined PEM, PKCS#12, or JCEKS). |
| `--proxy-cert PATH` / `--proxy-key PATH` | Proxy client certificate chain and private key as separate PEM files. |
| `--proxy-storepass PASS` | Password for `--proxy-keystore` (required for JCEKS, optional for PKCS#12). |
| `--proxy-cacert PATH` | CA bundle for verifying the proxy. Defaults to `--cacert`. |

`--proxy-keystore` and `--proxy-cert`/`--proxy-key` are mutually exclusive,
and all of these flags require an `https://` proxy URL. The proxy credential
must be a file on disk: PKCS#11, keychain, and SPIFFE Workload API sources
are only supported for the target credential. See
[Certificate Formats]({{< ref "formats.md" >}}) for the accepted file
formats.

```bash
ghostunnel client \
    --listen localhost:8080 \
    --target backend.internal:8443 \
    --keystore client.p12 \
    --cacert cacert.pem \
    --proxy https://proxy.example.com \
    --proxy-cert proxy-client.pem \
    --proxy-key proxy-client-key.pem \
    --proxy-cacert proxy-ca.pem
```

Like the other credential flags, these can also be set through environment
variables (`PROXY_KEYSTORE_PATH`, `PROXY_CERT_PATH`, `PROXY_KEY_PATH`,
`PROXY_KEYSTORE_PASS`, `PROXY_CACERT_PATH`). See
[Flags]({{< ref "flags.md" >}}).

### Reloading

The proxy credential and proxy CA bundle are reloaded together with the
target credential on `SIGHUP`, `SIGUSR1`, or `--timed-reload`, so a
short-lived proxy certificate can be rotated without restarting Ghostunnel.
Existing tunnels are not affected; new connections use the reloaded
certificate. See [Certificate Reloading]({{< ref "reloading.md" >}}).

## Landlock

On Linux, the [Landlock sandbox]({{< ref "general.md#landlock-sandboxing" >}})
automatically permits outbound connections to the proxy's port and read
access to the proxy credential files. No additional `--landlock-*` flags are
needed.
