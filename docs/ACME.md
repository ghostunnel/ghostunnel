ACME Support
============

To have Ghostunnel automatically obtain and renew a public TLS certificate via ACME,
use the `--auto-acme-cert=` flag (e.g. - `--auto-acme-cert=myservice.example.com`).
You must also specify an email address so you will get notices from the CA about
potentially important certificate lifecycle events. Specify the email address with
the `--auto-acme-email=` flag. To use this feature, you must also specify the
`--auto-acme-agree-to-tos` flag to indicate your explicit agreement with the CA's
Terms of Service.

Ghostunnel defaults to using Let's Encrypt, but you can specify a different ACME
CA URL using the `--auto-acme-ca=` flag. If you wish to test Ghostunnel's ACME
features against a non-production ACME CA, use the `--auto-acme-testca=` flag.
If `--auto-acme-testca` is specified, all ACME interaction will be with the
specified test CA URL and the `--auto-acme-ca=` flag will be ignored.

Note that ACME is only supported in server mode. Additionally, Ghostunnel must
either be listening to a public interface on tcp/443, or somehow have a public
tcp/443 listening interface forwarded to it (such as a systemd socket,
iptables, etc.). Public DNS records must exist for a valid public DNS FQDN that
resolves to the public listening interface IP.
