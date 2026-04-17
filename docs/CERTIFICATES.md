---
title: Certificate Formats
description: Supported certificate and key formats, how to prepare them, and how Ghostunnel selects the right loader.
weight: 12
---

Ghostunnel supports several certificate and private key formats. The format
is auto-detected from the file extension or by inspecting the first few
bytes, so you don't need to specify it explicitly.

## Formats at a glance

| Format | Extensions | Flag | Notes |
|--------|-----------|------|-------|
| PEM (separate files) | `.pem`, `.crt` + `.pem` | `--cert` + `--key` | Most common; leaf cert must be first in chain |
| PEM (combined) | `.pem` | `--keystore` | Single file with cert chain and private key |
| PKCS#12 | `.p12`, `.pfx` | `--keystore` | Binary bundle; optional `--storepass` for password |
| JCEKS | `.jceks`, `.jks` | `--keystore` | Java keystore; requires `--storepass` |
| DER | `.der` | `--keystore` | Raw X.509 or PKCS#7; less common |

These options are mutually exclusive with each other and with `--use-workload-api`,
`--keychain-identity`, and PKCS#11 flags.

## PEM files (separate cert and key)

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

The certificate file must contain the **leaf certificate first**, followed by
any intermediate CA certificates:

```
-----BEGIN CERTIFICATE-----
(leaf / end-entity certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
(intermediate CA certificate)
-----END CERTIFICATE-----
```

The key file must contain a single PEM-encoded private key (RSA, ECDSA,
or Ed25519).

## PEM keystore (combined file)

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
[Keychain Support]({{< ref "KEYCHAIN.md" >}})).

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

Ghostunnel can read Java keystores in JCEKS or JKS format. This is mainly
useful when migrating from a Java-based TLS terminator:

```bash
ghostunnel server \
    --keystore server.jceks \
    --storepass <password> \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

## CA bundle

The `--cacert` flag accepts a PEM file containing one or more trusted CA
certificates. If omitted, Ghostunnel uses the system trust store.

To build a CA bundle from individual certificates:

```bash
cat root-ca.pem intermediate-ca.pem > cacert.pem
```

## Format auto-detection

Ghostunnel detects the format in this order:

1. **File extension**: `.pem`/`.crt` → PEM, `.p12`/`.pfx` → PKCS#12,
   `.jceks`/`.jks` → JCEKS, `.der` → DER.
2. **Magic bytes**: if the extension is ambiguous, the first bytes of the file
   are inspected (e.g. `-----BEGIN` → PEM, ASN.1 sequence → PKCS#12 or DER).

In practice, just use the right file extension and Ghostunnel will do the
right thing.

## Common operations

### Inspect a PEM certificate

```bash
openssl x509 -in server-cert.pem -noout -text
```

### Inspect a PKCS#12 file

```bash
openssl pkcs12 -in server.p12 -info -nokeys
```

### Convert PKCS#12 to PEM

```bash
# Extract certificate chain
openssl pkcs12 -in server.p12 -clcerts -nokeys -out server-cert.pem

# Extract private key
openssl pkcs12 -in server.p12 -nocerts -nodes -out server-key.pem
```

### Verify a certificate chain

```bash
openssl verify -CAfile cacert.pem server-cert.pem
```
