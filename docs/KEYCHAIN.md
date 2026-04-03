---
title: Keychain Support
description: Load certificates and private keys from the macOS Keychain or Windows Certificate Store, including hardware-backed keys.
weight: 50
---

If you have identities stored in the macOS Keychain or Windows Certificate
Store, Ghostunnel can load certificates directly from them. This is useful
when you want private keys backed by the Secure Enclave on Touch ID MacBooks,
or when managing certificates through the OS is preferable to managing files
on disk.

### Selecting a certificate

Certificates from the keychain can be selected using one or both of the
following flags:

* `--keychain-identity` — match by the certificate's Common Name (CN) or
  serial number. Ghostunnel checks both fields and uses the first match.
* `--keychain-issuer` — match by the issuer's Common Name (CN).

When both flags are specified, Ghostunnel selects certificates where both
attributes match (logical AND).

On macOS, `--keychain-require-token` additionally requires the loaded
certificate to come from a physical hardware token (e.g. the Secure Enclave).
This flag is not available on Windows.

### macOS example

Load an identity from the login keychain by subject name:

```bash
ghostunnel client \
    --keychain-identity <common-name-or-serial> \
    --listen unix:/path/to/unix/socket \
    --target example.com:443 \
    --cacert cacert.pem
```

Or filter by issuer name:

```bash
ghostunnel client \
    --keychain-issuer <issuer-common-name> \
    --listen unix:/path/to/unix/socket \
    --target example.com:443 \
    --cacert cacert.pem
```

### Windows example

On Windows, `--keychain-identity` and `--keychain-issuer` work the same way
but search the Windows Certificate Store (the "MY" store for the current user):

```bash
ghostunnel client \
    --keychain-identity <common-name-or-serial> \
    --listen localhost:8080 \
    --target example.com:443 \
    --cacert cacert.pem
```

### Certificate reloading

Keychain certificates support reloading via `SIGHUP`/`SIGUSR1` or
`--timed-reload`. On reload, Ghostunnel re-queries the keychain for a
certificate matching the same identity/issuer criteria. If the certificate
has been updated in the keychain (e.g. renewed), the new certificate will
be used for subsequent connections.
