---
title: Certificate Formats
description: Supported certificate and key formats, how to prepare them, and how Ghostunnel selects the right loader.
weight: 10
---

Ghostunnel supports several certificate and private key formats. The format
is auto-detected from the file extension or by inspecting the first few
bytes, so you don't need to specify it explicitly.

## Formats at a Glance

| Format | Extensions | Flag | Notes |
|--------|-----------|------|-------|
| PEM (separate files) | `.pem`, `.crt` + `.pem` | `--cert` + `--key` | Most common; leaf cert must be first in chain |
| PEM (combined) | `.pem` | `--keystore` | Single file with cert chain and private key |
| PKCS#12 | `.p12`, `.pfx` | `--keystore` | Binary bundle; optional `--storepass` for password |
| JCEKS | `.jceks`, `.jks` | `--keystore` | Java keystore (JCEKS; JKS certs only — convert JKS private keys to PKCS#12); requires `--storepass` |

These options are mutually exclusive with each other and with `--use-workload-api`,
`--keychain-identity`, and PKCS#11 flags.

## PEM Files (Separate Cert and Key)

Pass the certificate chain and private key as two separate PEM files:

```bash
ghostunnel server \
    --cert server-chain.pem \
    --key server-key.pem \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

**Order matters.** List your server's certificate first (the *leaf*), then
each intermediate CA in chain order, working up toward the root. Ghostunnel
sends the chain to clients in this exact order during the TLS handshake, so
the client can verify a path back to a root it already trusts. The root
itself is not included — the client must already have it.

```pem {file="server-chain.pem"}
# 1. Your server's certificate (the leaf / end-entity cert).
-----BEGIN CERTIFICATE-----
... your server's certificate ...
-----END CERTIFICATE-----

# 2. Intermediate CA that signed the leaf.
-----BEGIN CERTIFICATE-----
... intermediate CA certificate ...
-----END CERTIFICATE-----

# 3. (Optional) any further intermediates, each signed by the next one up.
```

The key file must contain a single PEM-encoded private key (RSA, ECDSA,
or Ed25519).

## PEM Keystore (Combined File)

A single PEM file containing both the certificate chain and private key can
be passed with `--keystore`. The private key can appear anywhere in the file,
but the leaf certificate must still come before any intermediates:

```bash
ghostunnel server \
    --keystore server-combined.pem \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

To create a combined PEM file:

```bash
cat server-cert.pem intermediate.pem server-key.pem > server-combined.pem
```

## PKCS#12

PKCS#12 (`.p12` / `.pfx`) bundles the certificate chain and private key into a
single password-protected binary file. This is also the format used when
importing into the macOS Keychain or Windows Certificate Store (see
[Keychain Support]({{< ref "keychain.md" >}})).

```bash
ghostunnel server \
    --keystore server.p12 \
    --storepass <password> \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

To create a PKCS#12 file from PEM files:

```bash
openssl pkcs12 -export \
    -in server-cert.pem \
    -inkey server-key.pem \
    -certfile intermediate.pem \
    -out server.p12 \
    -passout pass:<password>
```

See the [openssl-pkcs12][openssl-pkcs12] man page for all options.

[openssl-pkcs12]: https://docs.openssl.org/master/man1/openssl-pkcs12/

## JCEKS

Ghostunnel can read Java keystores in JCEKS format, and can read trusted
certificates from JKS keystores. JKS keystores that contain a **private key**
(the usual case for a server keystore) are **not** supported directly, because
JKS uses Sun's proprietary key-protection algorithm. Convert such a keystore to
PKCS#12 first:

```bash
keytool -importkeystore \
    -srckeystore server.jks -srcstoretype JKS \
    -destkeystore server.p12 -deststoretype PKCS12
```

then pass `server.p12` to `--keystore`.

Reading Java keystores is mainly useful when migrating from a Java-based TLS
terminator:

```bash
ghostunnel server \
    --keystore server.jceks \
    --storepass <password> \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

## CA Bundle

The `--cacert` flag accepts a PEM file containing one or more trusted CA
certificates. If omitted, Ghostunnel uses the system trust store.

To build a CA bundle from individual certificates:

```bash
cat root-ca.pem intermediate-ca.pem > cacert.pem
```

## Format Auto-Detection

Ghostunnel detects the format of `--keystore` first from the file extension
(`.pem`, `.crt`, `.p12`, `.pfx`, `.jceks`, `.jks`, and similar), and falls back
to inspecting the first few bytes when the extension is unrecognized. This
supports PEM, JCEKS and PKCS#12 formats. Files passed to `--cert`/`--key` skip
auto-detection and are always parsed as PEM.

## Common Operations

### Inspect a PEM Certificate

```bash
openssl x509 -in server-cert.pem -noout -text
```

### Inspect a PKCS#12 File

```bash
openssl pkcs12 -in server.p12 -info -nokeys
```

### Convert PKCS#12 to PEM

```bash
# Extract the leaf certificate
openssl pkcs12 -in server.p12 -clcerts -nokeys -out server-cert.pem

# Extract CA/intermediate certificates
openssl pkcs12 -in server.p12 -cacerts -nokeys -out ca-chain.pem

# Extract private key
openssl pkcs12 -in server.p12 -nocerts -nodes -out server-key.pem
```

### Verify a Certificate Chain

```bash
openssl verify -CAfile cacert.pem server-cert.pem
```
