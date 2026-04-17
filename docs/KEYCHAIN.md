---
title: Keychain Support
description: Load certificates and private keys from the macOS Keychain or Windows Certificate Store, including hardware-backed keys.
weight: 50
---

Ghostunnel can load certificates and private keys directly from the macOS
Keychain or Windows Certificate Store. This lets you use Secure Enclave-backed
keys on Touch ID MacBooks, hardware-backed keys via CNG on Windows, or simply
manage certificates through the OS instead of as files on disk.

### Prerequisites: creating a PKCS#12 bundle

Both macOS and Windows import certificates from [PKCS#12][openssl-pkcs12]
(`.p12` / `.pfx`) files. If you have a PEM certificate and key, bundle them
first:

```bash
openssl pkcs12 -export \
    -in server-cert.pem \
    -inkey server-key.pem \
    -out server.p12 \
    -passout pass:<password>
```

If you also need to include intermediate CA certificates in the bundle, add
`-certfile intermediate-ca.pem`.

[openssl-pkcs12]: https://docs.openssl.org/master/man1/openssl-pkcs12/

### macOS: importing into the Keychain

**Using the CLI** (recommended for automation):

```bash
security import server.p12 \
    -k ~/Library/Keychains/login.keychain-db \
    -f pkcs12 \
    -P <password> \
    -A
```

The `-A` flag allows all applications to access the imported key without a
confirmation prompt. Omit it if you prefer per-application access control.

You can also **double-click the `.p12` file** in Finder or use the
[Keychain Access][apple-keychain-access] app to import through the GUI.

**Verify** the import succeeded:

```bash
security find-identity -v
```

This lists all identities (certificate + private key pairs) in your keychain
search list. Look for your certificate's Common Name in the output.

See also Apple's [Keychain Services documentation][apple-keychain-services]
and [TN3137: On Mac keychain APIs and implementations][apple-tn3137].

[apple-keychain-access]: https://support.apple.com/guide/keychain-access/add-certificates-to-a-keychain-kyca2431/mac
[apple-keychain-services]: https://developer.apple.com/documentation/security/keychain-services
[apple-tn3137]: https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains

### macOS: Secure Enclave and hardware tokens

On Touch ID MacBooks, private keys can live in the Secure Enclave. Pass
`--keychain-require-token` so Ghostunnel only loads keys backed by a hardware
token (e.g. the Secure Enclave or a smart card):

```bash
ghostunnel server \
    --keychain-identity <common-name> \
    --keychain-require-token \
    --listen localhost:8443 \
    --target localhost:8080 \
    --cacert cacert.pem \
    --allow-ou=client
```

This flag is only available on macOS and has no effect on Windows.

See Apple's [Protecting keys with the Secure Enclave][apple-secure-enclave]
and the [Secure Enclave security overview][apple-se-overview] for more on
hardware-backed keys.

[apple-secure-enclave]: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
[apple-se-overview]: https://support.apple.com/guide/security/sec59b0b31ff/web

### Windows: importing into the Certificate Store

**Using certutil** (recommended for automation):

```bash
certutil -f -p <password> -user -importpfx MY server.p12
```

This imports the certificate and private key into the current user's "MY"
(Personal) store. The `-user` flag targets the current user context; replace
it with `-enterprise` to import into the Local Machine store instead.

**Using PowerShell**:

```powershell
Import-PfxCertificate -FilePath server.p12 `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Password (ConvertTo-SecureString -String "<password>" -AsPlainText -Force)
```

**Verify** the import:

```powershell
Get-ChildItem Cert:\CurrentUser\My | Format-Table Subject, Thumbprint, NotAfter
```

**Which stores does Ghostunnel search?** When `--keychain-identity` is used
on Windows, Ghostunnel searches three stores in order:

1. **MY** (Current User), the personal certificate store
2. **CURRENT_SERVICE**, the current service account's certificates
3. **LOCAL_MACHINE**, machine-wide certificates (may require elevation)

See Microsoft's [certutil reference][ms-certutil],
[System Store Locations][ms-store-locations], and the
[Import-PfxCertificate][ms-import-pfx] cmdlet docs for more.

[ms-certutil]: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
[ms-store-locations]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/system-store-locations
[ms-import-pfx]: https://learn.microsoft.com/en-us/powershell/module/pki/import-pfxcertificate

### Selecting a certificate

Certificates from the keychain can be selected using one or both of the
following flags:

* `--keychain-identity`: match by the certificate's Common Name (CN) or
  serial number. Ghostunnel checks both fields and uses the first match.
* `--keychain-issuer`: match by the issuer's Common Name (CN).

When both flags are specified, Ghostunnel selects certificates where both
attributes match (logical AND). If multiple certificates match, the one with
the latest expiration date (NotAfter) is used.

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

### Removing certificates

**macOS**: remove an identity (certificate + private key) by Common Name:

```bash
security delete-identity -c <common-name>
```

Or use the Keychain Access app to find and delete the certificate in the GUI.

**Windows**: remove via PowerShell:

```powershell
Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -match "CN=<common-name>" } |
    Remove-Item -DeleteKey
```

The `-DeleteKey` flag also removes the private key. You can alternatively
use `certutil -delstore MY <serial-or-thumbprint>`.

### Troubleshooting

**macOS: certificate not found**
- Check the keychain search list: `security list-keychains`
- Unlock the keychain if locked: `security unlock-keychain`
- List available identities: `security find-identity -v`
- Make sure the CN or serial matches what you passed to `--keychain-identity`

**Windows: certificate not found**
- List certs in the store: `Get-ChildItem Cert:\CurrentUser\My`
- If using the Local Machine store, make sure Ghostunnel runs with sufficient permissions
- Make sure the CN or serial matches what you passed to `--keychain-identity`

**Access denied / permission errors**
- **macOS**: the keychain may prompt for access. Use `-A` during import to allow all apps, or grant access to Ghostunnel specifically in Keychain Access.
- **Windows**: the account running Ghostunnel needs read access to the private key. See [Manage private key permissions][ms-private-key-perms].

[ms-private-key-perms]: https://learn.microsoft.com/en-us/windows-server/identity/ad-fs/technical-reference/manage-ssl-certificates-ad-fs-wap#manage-private-key-permissions
