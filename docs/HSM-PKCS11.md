---
title: HSM/PKCS#11 Support
description: Load private keys from hardware security modules via the PKCS#11 interface.
weight: 40
---

Ghostunnel has support for loading private keys from PKCS#11 modules, which
should work with any hardware security module that exposes a PKCS#11 interface.
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

To launch Ghostunnel with the SoftHSM-backed PKCS11 key:

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
used to select the private key to be used from the PKCS11 module. It's also possible
to use environment variables to set PKCS11 options instead of flags (via
`PKCS11_MODULE`, `PKCS11_TOKEN_LABEL` and `PKCS11_PIN`), useful if you don't
want to show the PIN on the command line.

Note that `--cert` needs to point to the certificate chain that corresponds
to the private key in the PKCS#11 module, with the leaf certificate being the
first certificate in the chain. Ghostunnel currently cannot read the
certificate chain directly from the module.

### Certificate hotswapping

When using PKCS#11, certificate hotswapping (via `SIGHUP`/`SIGUSR1` or
`--timed-reload`) reloads only the certificate from disk. The private key in
the HSM is assumed to remain the same. This means the updated or reissued
certificate must still match the private key that was loaded from the HSM.

Note that Landlock sandboxing is automatically disabled when PKCS#11 is used,
as PKCS#11 modules are opaque shared libraries that may need access to
arbitrary files and sockets.

### Inspecting PKCS#11 state

If you need to inspect the state of a PKCS11 module/token, we recommend the
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

[pkcs11-tool]: https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#using-pkcs11-tool
