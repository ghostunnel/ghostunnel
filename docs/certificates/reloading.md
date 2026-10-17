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

{{% since "v1.12.0" %}}
In client mode, a reload also re-reads the proxy client certificate and
proxy CA bundle (`--proxy-keystore` or `--proxy-cert`/`--proxy-key`, and
`--proxy-cacert`), if configured. See
[Outbound Proxies](../../networking/outbound-proxy/).
{{% /since %}}

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

## Session Resumption

Ghostunnel supports TLS session resumption. A client that resumes a session
skips the full handshake and reuses the access control decision made when
the session was first established: `--allow-*` flags and `--allow-policy`
are not re-evaluated on a resumed connection. This is what makes resumption
cheap.

A reload, whether triggered by a signal or by `--timed-reload`, invalidates
existing sessions. Each client's next connection is therefore a full handshake
against the reloaded certificate, CA bundle and policy, and a policy change
takes effect for resuming clients as soon as the reload completes (the
`/_status` endpoint reports `listening` again). Connections already
established are unaffected.

{{% since "v1.12.0" %}}
This also holds for the SPIFFE Workload API. Certificates and trust bundles
pushed by the SPIFFE provider take effect for new full handshakes without a
reload, but a client that resumes a session keeps the decision from its
original handshake until the next reload invalidates the session.
{{% /since %}}

The cost is one extra full handshake per client per reload, so a short
`--timed-reload` interval reduces the benefit of resumption. Resumption is
also refused once the client certificate in the session has expired.

## Zero-Downtime Binary Replacement

Reloading covers credentials, not the binary itself. To replace a running
Ghostunnel, note that it binds its listening socket with `SO_REUSEPORT` on
platforms that support it (Linux, macOS, FreeBSD, NetBSD, OpenBSD, and
DragonFly BSD). A new Ghostunnel process can be started on the same
host/port before the old one is terminated, to minimize dropped connections
(or avoid them entirely, depending on how the OS implements `SO_REUSEPORT`).
Combine this with [graceful shutdown]({{< ref "graceful-shutdown.md" >}}) of
the old process to drain its remaining connections.
