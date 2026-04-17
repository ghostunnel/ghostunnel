# Documentation Improvements

Ideas for making the Ghostunnel documentation more useful and complete.

## Structure / Navigation

- `_index.md` could include a short "which doc do I need?" guide, e.g. "want mTLS
  between services? start here", "need automatic certs? see ACME", "managing certs
  through the OS? see Keychain or HSM". Right now there's no guided entry point.
- The FLAGS.md quick reference could link each flag row to the relevant section in
  the detailed doc (e.g. `--proxy-protocol` links to a PROXY protocol section,
  `--landlock` links to SECURITY.md).

## Missing Topics

- **PROXY protocol v2**: `--proxy-protocol` is mentioned in FLAGS.md but there's no
  explanation of what it does, when you'd use it, or how the backend should consume
  the header.
- **`--proxy` flag (HTTP CONNECT / SOCKS5)**: useful for corporate environments,
  worth at least a short section covering client-mode proxy support.
- **Certificate formats**: the differences between `--keystore` (PKCS#12 or combined
  PEM), `--cert`/`--key` (separate PEM), and how cert chains should be ordered
  (leaf first). This is a common source of confusion.
- **Quick start / tutorial**: every doc jumps straight into flags and reference. A
  single "get ghostunnel running in 5 minutes" page with a self-signed CA would
  help newcomers.
- **Graceful shutdown behavior**: `--shutdown-timeout`, what happens to in-flight
  connections, how SIGTERM/SIGINT are handled, how `/_shutdown` interacts with this.

## Existing Content Gaps

- `SECURITY.md` lists cipher suites but doesn't explain why these were chosen or how
  to verify what's negotiated (e.g. `openssl s_client -connect`).
- `ACME.md` doesn't mention how to revoke or force-renew a certificate, or where
  exactly certmagic stores things on each OS.
- `METRICS.md` doesn't show a Grafana/Prometheus scrape config example, which would
  make the Prometheus endpoint more immediately useful.
- `SOCKET-ACTIVATION.md` shows full unit files but doesn't explain how to actually
  install and enable them (`systemctl enable`, `launchctl load`).
- The OPA section in `ACCESS-FLAGS.md` doesn't explain how to build a bundle from a
  `.rego` file (`opa build`), just says "policy bundle must be present on disk."

## Consistency

- Some docs use `###` headings exclusively (KEYCHAIN, ACME, WATCHDOG), others mix
  `##` and `###` (ACCESS-FLAGS, METRICS, SECURITY). Standardizing would help.
- The Secure Enclave section in KEYCHAIN.md only shows a `server` example; the
  existing macOS/Windows examples only show `client`. Having both modes in each
  section (or a note that the flags work identically in both) would reduce guesswork.
