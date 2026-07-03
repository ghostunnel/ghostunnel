---
title: Ghostunnel
description: A simple TLS proxy with mutual authentication support
intro: >
  Ghostunnel is a TLS proxy with mutual authentication support for securing
  non-TLS services. It sits in front of (or alongside) a backend service and
  handles the TLS layer, so the service itself never has to.
outro: >
  Ghostunnel also supports PROXY protocol v2, has a status port with rich
  metrics, can be tuned with connection limits and timeouts, supports
  systemd/launchd socket activation, and more. See the [docs](docs/)
  for details.
modes:
  - name: Server mode
    flow: ["TLS", "ghostunnel", "plaintext"]
    text: >
      Accepts TLS connections and forwards them as plaintext to a backend.
      Terminate mutual TLS in front of services that don't speak it.
  - name: Client mode
    flow: ["plaintext", "ghostunnel", "TLS"]
    text: >
      Accepts plaintext connections on a TCP or UNIX socket and forwards them
      over TLS to a remote service. Add client certificates to anything.
features:
  - icon: shield
    title: Mutual TLS Authentication
    url: /docs/security/
    text: >
      Enforces mutual TLS by requiring valid client certificates on every
      connection, with hostname verification and modern TLS defaults.
  - icon: sliders
    title: Fine-Grained Access Control
    url: /docs/security/access-flags/
    text: >
      Restrict access based on certificate fields (e.g. SPIFFE ID), or
      write declarative authorization policies with Open Policy Agent.
  - icon: refresh
    title: Certificate Hotswapping
    url: /docs/certificates/reloading/
    text: >
      Reload certificates without restarting via SIGHUP or timed
      reload intervals, enabling the use of short-lived certificates.
  - icon: key
    title: Flexible Certificate Sources
    url: /docs/certificates/
    text: >
      Load keys from PEM/PKCS#12 files, ACME (Let's Encrypt), hardware modules
      (PKCS#11), macOS Keychain, Windows Certificate Store, or SPIFFE Workload API.
  - icon: lock
    title: Secure by Default
    url: /docs/security/general/
    text: >
      Listeners and targets are restricted to localhost and UNIX sockets unless
      explicitly overridden, and Landlock sandboxing is enabled on Linux.
  - icon: package
    title: Runs Anywhere
    url: /docs/getting-started/quickstart/#install-ghostunnel
    text: >
      Ships as a single static Go binary with no runtime dependencies. Runs
      on Linux, macOS, Windows, and the BSDs.
---

## Getting Started

See the [Quick Start](/docs/getting-started/quickstart/) guide for installation, generating
test certificates, and running your first tunnel. The full documentation is
available under [Docs](/docs/). Pre-built binaries are available on the
[Releases](/releases/) page and via
[Docker](https://hub.docker.com/r/ghostunnel/ghostunnel). See [Docker
Images]({{< ref "docker.md" >}}) for available image variants.
