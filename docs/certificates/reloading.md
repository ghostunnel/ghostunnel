---
title: Certificate Reloading
description: Reload certificates, CA bundles, and OPA policies without restarting, enabling the use of short-lived certificates.
weight: 60
aliases:
  - /docs/reloading/
---

Ghostunnel can reload its credentials at runtime without dropping existing
connections, enabling the use of short-lived certificates. Once a reload
succeeds, new connections use the reloaded configuration; existing
connections are not affected.

## Reload Triggers

* **`SIGHUP` / `SIGUSR1`** (Unix only): send either signal to the process to
  trigger an immediate reload. Under systemd, `systemctl reload` sends
  `SIGHUP` for you (see [Systemd]({{< ref "systemd.md" >}})); under launchd,
  use `launchctl kill SIGHUP` (see [Launchd]({{< ref "launchd.md" >}})).
* **`--timed-reload DURATION`** (all platforms, including Windows): reload
  on a fixed interval, e.g. `--timed-reload 300s`. This is the only reload
  mechanism on Windows, which has no reload signals.

## What Gets Reloaded

A reload re-reads from disk:

* The certificate and private key (`--keystore` or `--cert`/`--key`).
* The CA bundle (`--cacert`).
* OPA policy bundles (`--allow-policy` / `--verify-policy`), if configured.
  See [Access Control Flags]({{< ref "access-flags.md" >}}).

## Source-Specific Behavior

* **PKCS#11 / HSM**: only the certificate is reloaded from disk; the private
  key in the HSM is assumed unchanged, so the new certificate must still
  match it. See [HSM/PKCS#11]({{< ref "hsm-pkcs11.md" >}}).
* **Keychain**: a reload re-queries the macOS Keychain or Windows
  Certificate Store using the same identity/issuer criteria. See
  [Keychain]({{< ref "keychain.md" >}}).
* **SPIFFE Workload API**: certificates and trust bundles are pushed by the
  SPIFFE provider and picked up automatically; no manual reload is needed.
  See [SPIFFE Workload API]({{< ref "spiffe-workload-api.md" >}}).
* **ACME**: certmagic renews certificates automatically in the background;
  a reload only refreshes the CA bundle. See [ACME]({{< ref "acme.md" >}}).
* **System trust store**: without `--cacert`, peers are verified against the
  system trust store, which a reload cannot refresh. On Linux and the BSDs,
  Go reads the system roots once per process (honoring `SSL_CERT_FILE` and
  `SSL_CERT_DIR`), so a change made while Ghostunnel runs (by
  `update-ca-certificates`, say) is picked up only on restart. Pass
  `--cacert` explicitly if you need those roots to be reloadable. On macOS
  and Windows, verification goes through the platform verifier, which always
  consults the current system store, so changes there take effect without a
  reload. Note that Ghostunnel built with Go 1.27 or later also honors
  `SSL_CERT_FILE` and `SSL_CERT_DIR` on macOS and Windows: when either is
  set, roots are read from disk and verified by Go rather than by the
  platform, which brings back the restart requirement above.
  `GODEBUG=x509sslcertoverrideplatform=0` restores the platform verifier.

## Session Resumption

A client may be given a session ticket that lets it skip a full handshake on
its next connection. Two rules govern what a reload means for those clients:

* **Access control is enforced on resumed connections** (*since v1.12.0*).
  A client reconnecting with a session ticket is checked against the access
  control flags and OPA policy in force at that moment, so revoking access
  through a policy reload takes effect immediately. Before v1.12.0 these
  checks ran only on full handshakes, and a client holding a ticket kept the
  access it had when the ticket was issued.
* **A reload invalidates outstanding session tickets.** Clients fall back to
  a full handshake on their next connection, which is how a rotated
  certificate reaches them: a resumed handshake carries no certificate at
  all. Connections already established are unaffected. The cost is one extra
  full handshake per client per reload, so a short `--timed-reload` interval
  largely disables resumption.

Certificates are not re-verified on a resumed connection; that happened when
the session was established. Only the access control decision is re-made.
Under the SPIFFE Workload API nothing is reloaded from disk, so a reload does
not invalidate tickets there; see
[SPIFFE Workload API]({{< ref "spiffe-workload-api.md" >}}).

## Zero-Downtime Binary Replacement

Reloading covers credentials, not the binary itself. To replace a running
Ghostunnel, note that it binds its listening socket with `SO_REUSEPORT` on
platforms that support it (Linux, macOS, FreeBSD, NetBSD, OpenBSD, and
DragonFly BSD). A new Ghostunnel process can be started on the same
host/port before the old one is terminated, to minimize dropped connections
(or avoid them entirely, depending on how the OS implements `SO_REUSEPORT`).
Combine this with [graceful shutdown]({{< ref "graceful-shutdown.md" >}}) of
the old process to drain its remaining connections.
