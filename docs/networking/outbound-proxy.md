---
title: Outbound Proxies
description: Reach the target through an HTTP CONNECT, HTTPS CONNECT, or SOCKS5 proxy in client mode, including client certificate authentication to the proxy.
weight: 20
since: v1.12.0
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
| `http://host:port` | Plaintext | HTTP `CONNECT` tunnel. Port defaults to `80`. |
| `https://host:port` | TLS | HTTP `CONNECT` tunnel over TLS. Port defaults to `443`. Supports client certificate authentication to the proxy (see below). |
| `socks5://host:port` | Plaintext | SOCKS5 tunnel. Port defaults to `1080`. `socks5h://` is accepted as an alias; with either scheme, the proxy resolves the target hostname. |

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

Credentials embedded in the proxy URL (`http://user:pass@proxy`) are sent
to HTTP CONNECT proxies as basic authentication (`Proxy-Authorization`) and
to SOCKS5 proxies as username/password authentication. With `http://` and
`socks5://` proxies they cross the network in plaintext; an `https://` proxy
protects them, or can replace them with a client certificate as described
below.

## HTTPS Proxies

With an `https://` proxy URL, Ghostunnel first performs a TLS handshake with
the proxy and then sends the `CONNECT` request inside that session. The
proxy's certificate is checked against the hostname in the proxy URL and
verified against the first of these that is set:

1. `--proxy-cacert`
2. `--cacert`
3. the system trust store

Set `--proxy-cacert` when the proxy and the target use different CAs, for
example a proxy with a publicly trusted certificate in front of a private
PKI.

Only the proxy's certificate chain and hostname are verified. The
`--verify-*` flags, `--verify-policy`, and `--override-server-name` apply to
the target at the other end of the tunnel, not to the proxy. A proxy that
fails verification is never sent a `CONNECT` request, and the failure shows
up as a backend error on the [status endpoint]({{< ref "metrics.md" >}}).

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
and `--proxy-storepass` can only be used with `--proxy-keystore`. All of these
flags require an `https://` proxy URL. The proxy credential
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

## Timeouts

`--connect-timeout` is a single budget for the whole connection setup, not
a separate limit for each step. The TCP connection to the proxy, the TLS
handshake with an `https://` proxy, the `CONNECT` or SOCKS5 exchange with the
proxy, and the TLS handshake with the target through the tunnel must all
complete within it. A proxy that accepts the connection but never answers
makes the connection fail once the timeout expires. Once the tunnel is
established, `--idle-timeout`, `--close-timeout`, and `--max-conn-lifetime`
apply just as they do to a direct connection. See
[Timeouts & Connection Lifecycle]({{< ref "timeouts.md" >}}).

## Landlock

On Linux, the [Landlock sandbox]({{< ref "general.md#landlock-sandboxing" >}})
automatically permits outbound connections to the proxy's port and read
access to the proxy credential files. No additional `--landlock-*` flags are
needed.
