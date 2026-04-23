---
title: HSM/PKCS#11 Support
description: Load private keys from hardware security modules via the PKCS#11 interface.
weight: 40
aliases:
  - /docs/hsm-pkcs11/
---

Ghostunnel has support for loading private keys from [PKCS#11][pkcs11-spec]
modules, which should work with any hardware security module that exposes a
PKCS#11 interface.
An easy way to test the PKCS#11 interface for development purposes is with
[SoftHSM][softhsm]. Note that CGO is required in order for PKCS#11 support to
work.

[softhsm]: https://github.com/opendnssec/SoftHSMv2

To import the server test key into SoftHSM, for example:

```bash
softhsm2-util --init-token \
    --slot 0 \
    --label ghostunnel-server \
    --so-pin 1234 \
    --pin 1234

softhsm2-util --id 01 \
    --token ghostunnel-server \
    --label ghostunnel-server \
    --import test-keys/server-pkcs8.pem \
    --so-pin 1234 \
    --pin 1234
```

To launch Ghostunnel with the SoftHSM-backed PKCS#11 key:

```bash
ghostunnel server \
    --cert test-keys/server-cert.pem \
    --pkcs11-module /path/to/libsofthsm2.so \
    --pkcs11-token-label ghostunnel-server \
    --pkcs11-pin 1234 \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert test-keys/cacert.pem \
    --allow-cn client
```

The `--pkcs11-module`, `--pkcs11-token-label` and `--pkcs11-pin` flags can be
used to select the private key to be used from the PKCS#11 module. It's also possible
to use environment variables to set PKCS#11 options instead of flags (via
`PKCS11_MODULE`, `PKCS11_TOKEN_LABEL` and `PKCS11_PIN`), useful if you don't want to show the PIN on the command line.

Note that `--cert` needs to point to the certificate chain that corresponds
to the private key in the PKCS#11 module, with the leaf certificate being the
first certificate in the chain (see
[Certificate Formats]({{< ref "formats.md" >}})). Ghostunnel currently
cannot read the certificate chain directly from the module.

## Using a YubiKey

[YubiKey][yubikey] 4 and 5 series support the [PIV (FIPS 201)][piv] standard,
which exposes a PKCS#11 interface via the [YKCS11][ykcs11] module, so you
can use a YubiKey to hold Ghostunnel's private key in hardware.

[yubikey]: https://www.yubico.com
[piv]: https://developers.yubico.com/PIV/
[ykcs11]: https://developers.yubico.com/yubico-piv-tool/YKCS11/

### Prerequisites

You'll need `yubico-piv-tool`, which ships the CLI and the `libykcs11`
PKCS#11 module:

```bash
# macOS
brew install yubico-piv-tool

# Debian/Ubuntu
apt install yubico-piv-tool ykcs11
```

The module lives in different places depending on your platform:

| Platform              | Typical path                                    |
|-----------------------|-------------------------------------------------|
| macOS (Apple Silicon) | `/opt/homebrew/lib/libykcs11.dylib`              |
| macOS (Intel)         | `/usr/local/lib/libykcs11.dylib`                 |
| Linux (x86_64)       | `/usr/lib/x86_64-linux-gnu/libykcs11.so` or `/usr/local/lib/libykcs11.so` |

### PIV slots

YubiKey PIV has several key slots. For TLS with Ghostunnel, you'll
usually want slot **9a** (Authentication):

| Slot | Purpose              | Typical use              |
|------|----------------------|--------------------------|
| 9a   | Authentication       | TLS client/server certs  |
| 9c   | Digital Signature    | Code/document signing    |
| 9d   | Key Management       | Encryption               |
| 9e   | Card Authentication  | Physical access          |

### Generating a Key and Certificate

Generate a key pair on the YubiKey itself (the private key never leaves
the device):

```bash
# Generate an RSA 2048 key in slot 9a
yubico-piv-tool -s 9a -a generate -A RSA2048 -o public-key.pem

# Create a certificate signing request (CSR)
yubico-piv-tool -s 9a -a verify-pin -a request-certificate \
    -S '/CN=my-server/' -i public-key.pem -o csr.pem
```

Sign the CSR with your CA, then import the signed certificate back:

```bash
yubico-piv-tool -s 9a -a import-certificate -i server-cert.pem
```

### Exporting the Certificate for Ghostunnel

Ghostunnel reads the certificate chain from disk, not from the PKCS#11
module, so you'll need to export it:

```bash
yubico-piv-tool -s 9a -a read-certificate -o server-cert.pem
```

If your CA has an intermediate, concatenate them into a chain (leaf first):

```bash
cat server-cert.pem intermediate.pem > chain.pem
```

### Launching Ghostunnel with a YubiKey

```bash
ghostunnel server \
    --cert chain.pem \
    --pkcs11-module /opt/homebrew/lib/libykcs11.dylib \
    --pkcs11-token-label "YubiKey PIV #12345678" \
    --pkcs11-pin 123456 \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-cn client
```

The default PIV PIN is `123456`. Change it before doing anything real. To
keep the PIN off the command line, use the `PKCS11_PIN` environment variable
instead of `--pkcs11-pin`.

To find the correct token label for your YubiKey:

```bash
pkcs11-tool --module /opt/homebrew/lib/libykcs11.dylib -L
```

### Debugging

If things aren't working, set `YKCS11_DBG` (values 1–9) for verbose output
from the YKCS11 module:

```bash
YKCS11_DBG=1 ghostunnel server ...
```

`pkcs11-tool` is also handy for poking around on the YubiKey:

```bash
# List available slots/tokens
pkcs11-tool --module /path/to/libykcs11.dylib -L

# List objects (keys, certificates) on the token
pkcs11-tool --module /path/to/libykcs11.dylib -O
```

## Certificate Hotswapping

When using PKCS#11, certificate hotswapping (via `SIGHUP`/`SIGUSR1` or
`--timed-reload`) reloads only the certificate from disk. The private key
in the HSM stays put, so the new certificate still needs to match the key
that was loaded from the HSM.

Note that Landlock sandboxing is automatically disabled when PKCS#11 is used,
as PKCS#11 modules are opaque shared libraries that may need access to
arbitrary files and sockets.

## Inspecting PKCS#11 State

If you need to inspect the state of a PKCS#11 module/token, we recommend the
[`pkcs11-tool`][pkcs11-tool] utility from OpenSC. For example, it can be used
to list slots or read certificate(s) from a module:

```bash
# List slots on a module
pkcs11-tool --module $MODULE -L

# Show certificates (if any) available
pkcs11-tool --module $MODULE -O -y cert

# Read certificate chain given a label
pkcs11-tool --module $MODULE --label $LABEL --read-object -y cert
```

[pkcs11-spec]: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.html
[pkcs11-tool]: https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#using-pkcs11-tool
