HSM/PKCS#11 Support
===================

Ghostunnel has support for loading private keys from PKCS#11 modules, which
should work with any hardware security module that exposes a PKCS#11 interface.
An easy way to test the PKCS#11 interface for development purposes is with
[SoftHSM][softhsm]. Note that CGO is required in order for PKCS#11 support to
work (see [CROSS-COMPILE](docs/CROSS-COMPILE.md) for instructions to
cross-compile with CGO enabled).

[softhsm]: https://github.com/opendnssec/SoftHSMv2

To import the server test key into SoftHSM, for example:

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

To launch ghostunnel with the SoftHSM-backed PKCS11 key (on macOS):

    ghostunnel server \
        --cert test-keys/server-cert.pem \
        --pkcs11-module /usr/local/Cellar/softhsm/2.4.0/lib/softhsm/libsofthsm2.so \
        --pkcs11-token-label ghostunnel-server \
        --pkcs11-pin 1234 \
        --listen localhost:8443 \
        --target localhost:8080 \
        --cacert test-keys/cacert.pem \
        --allow-cn client

The `--pkcs11-module`, `--pkcs11-token-label` and `--pkcs11-pin` flags can be
used to select the private key to be used the PKCS11 module. It's also possible
to use environment variables to set PKCS11 options instead of flags (via
`PKCS11_MODULE`, `PKCS11_TOKEN_LABEL` and `PKCS11_PIN`), useful if you don't
want to show the PIN on the command line.

Note that `--cert` needs to point to the certificate chain that corresponds
to the private key in the PKCS#11 module, with the leaf certificate being the
first certificate in the chain. Ghostunnel doesn't have the ability to read
the certificate chain directly from the module at this point in time.

If you need to inspect the state of a PKCS11 module/token, we recommend the
[`pkcs11-tool`][pkcs11-tool] utility from OpenSC. For example, it can be used
to list slots or read certificate(s) from a module:

    # List slots on a module
    pkcs11-tool --module $MODULE -L

    # Show certificates (if any) available
    pkcs11-tool --module $MODULE -O -y cert

    # Read certificate chain given a label
    pkcs11-tool --module $MODULE --label $LABEL --read-object -y cert

[pkcs11-tool]: https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#using-pkcs11-tool
