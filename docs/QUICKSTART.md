---
title: Quick Start
description: Get Ghostunnel running with mTLS in 5 minutes using a self-signed CA.
weight: 5
---

This guide walks through setting up a Ghostunnel server and client with mutual
TLS, using a self-signed CA for testing.

## Install Ghostunnel

```bash
# Homebrew
brew install ghostunnel

# Or pull a Docker image (see Docker docs for all variants)
docker pull ghostunnel/ghostunnel:latest-distroless
```

Pre-built binaries are also available on the
[GitHub releases](https://github.com/ghostunnel/ghostunnel/releases) page.
See [Docker Images]({{< ref "DOCKER.md" >}}) for all available image variants.

To build from source (requires [Go](https://go.dev/doc/install)):

```bash
go tool mage go:build
```

## Generate test certificates

If you already maintain a PKI, you can skip this step and use your existing
certificates. The steps below are for generating test certificates for
testing and development purposes only.

You need a CA, a server certificate, and a client certificate. The rest of
this guide uses the paths from `test-keys/`, so adjust if you use a different
method.

**From the Ghostunnel repo** (requires Go):

```bash
go tool mage test:keys
```

This creates a `test-keys/` directory with everything you need: CA cert,
server cert+key, client cert+key, and PKCS#12 keystores.

**Using [mkcert](https://github.com/FiloSottile/mkcert)**:

```bash
mkcert -install
mkcert -cert-file test-keys/server-cert.pem -key-file test-keys/server-key.pem localhost 127.0.0.1
mkcert -client -cert-file test-keys/client-cert.pem -key-file test-keys/client-key.pem localhost
```

Note: mkcert sets SANs, not CNs, so use `--allow-dns localhost` instead of
`--allow-cn client` when authorizing clients. The CA cert is at
`$(mkcert -CAROOT)/rootCA.pem`, copy it to `test-keys/cacert.pem` to match
the paths below.

**Using [cfssl](https://github.com/cloudflare/cfssl)**: cfssl is a full-featured
PKI toolkit that can generate CAs and sign certificates. See the
[cfssl documentation](https://github.com/cloudflare/cfssl#readme) for usage.

**Using OpenSSL** manually: see the [openssl-req](https://docs.openssl.org/master/man1/openssl-req/)
and [openssl-x509](https://docs.openssl.org/master/man1/openssl-x509/) docs
for creating CAs and signing certificates.

## Start a backend service

Ghostunnel is protocol-agnostic and works with any TCP-based protocol, not
just HTTP. For this demo we'll use a simple HTTP server as the backend:

```bash
python3 -m http.server 8080 &
```

## Run Ghostunnel server

In a new terminal, start a server that listens for TLS on port 8443 and
forwards plaintext to the backend on port 8080. Only clients with CN=client
are allowed:

```bash
ghostunnel server \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cert test-keys/server-cert.pem \
    --key test-keys/server-key.pem \
    --cacert test-keys/cacert.pem \
    --allow-cn client
```

## Run Ghostunnel client

In another terminal, start a client that listens for plaintext on port 8081
and connects to the server over TLS:

```bash
ghostunnel client \
    --listen localhost:8081 \
    --target localhost:8443 \
    --cert test-keys/client-cert.pem \
    --key test-keys/client-key.pem \
    --cacert test-keys/cacert.pem
```

## Test the tunnel

In a third terminal, send a request through the tunnel:

```bash
curl http://localhost:8081
```

You should see the directory listing from the Python HTTP server. The
connection between client and server is encrypted with mTLS, even though
curl speaks plain HTTP.

<br>

![Tunnel diagram](/tunnel-diagram.svg)

The Ghostunnel client accepted a plaintext connection from curl, wrapped it
in TLS with the client certificate, and forwarded it to the Ghostunnel
server. The server verified the client cert (CN=client), unwrapped TLS, and
forwarded the plaintext request to the backend.

## Next steps

- [Command-Line Flags]({{< ref "FLAGS.md" >}}): full flag reference
- [Certificate Formats]({{< ref "CERTIFICATES.md" >}}): PEM, PKCS#12, JCEKS, and chain ordering
- [Access Control Flags]({{< ref "ACCESS-FLAGS.md" >}}): control who can connect (CN, OU, DNS/URI SAN, OPA)
- [ACME Support]({{< ref "ACME.md" >}}): automatic certificates from Let's Encrypt
- [Metrics & Profiling]({{< ref "METRICS.md" >}}): status port, Prometheus metrics, pprof
- [PROXY Protocol]({{< ref "PROXY-PROTOCOL.md" >}}): pass client connection metadata to backends
- [Socket Activation]({{< ref "SOCKET-ACTIVATION.md" >}}) and [Systemd Watchdog]({{< ref "WATCHDOG.md" >}}): run Ghostunnel as a service
