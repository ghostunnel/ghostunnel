Windows/macOS Keychain Support
==============================

Ghostunnel supports loading certificates from the Windows and macOS keychains.
This is useful if you have identities stored in your local keychain that you
want to use with Ghostunnel, e.g. if you want your private key(s) to be backed
by the SEP on newer Touch ID MacBooks.

Certificates from the keychain can be loaded by selecting them based on the
serial number or Common Name (CN) of the subject via the `--keychain-identity`
flag or Common Name (CN) of the issuer via the `--keychain-issuer` flag. In
addition to this, you can use the `--keychain-require-token` flag on macOS to
require the loaded certificate to come from a physical token by setting the
access group to `token`.

For example, to load an identity based on subject name from the login keychain:

    ghostunnel client \
        --keychain-identity <common-name-or-serial> \
        --listen unix:/path/to/unix/socket \
        --target example.com:443 \
        --cacert test-keys/cacert.pem

Or, if you'd like to load an identity by filtering on issuer name:

    ghostunnel client \
        --keychain-issuer <issuer-common-name> \
        --listen unix:/path/to/unix/socket \
        --target example.com:443 \
        --cacert test-keys/cacert.pem

Both commands above launch a ghostunnel instance that uses the certificate and
private key for the selected keychain identity to proxy plaintext connections from
a given UNIX socket to example.com:443. Note that combining both the identity and
issuer flags in one command will cause ghostunnel to select certificates where both
attributes match (matching with AND on both subject name/issuer).
