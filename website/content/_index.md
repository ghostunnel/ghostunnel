---
title: Ghostunnel
description: A simple TLS proxy with mutual authentication support
---

Ghostunnel is a TLS proxy with mutual authentication support for securing
non-TLS services. It runs in one of two modes:

* **Server mode**: accepts TLS connections and forwards them as plaintext to a
  backend.
* **Client mode**: accepts plaintext connections on a TCP or UNIX socket and
  forwards them over TLS to a remote service.

## Key Features

* **Authentication & Authorization**: Enforces mutual TLS authentication by
  requiring valid client certificates. Supports fine-grained access control
  checks on certificate fields (CN, OU, DNS/URI SAN), and declarative
  authorization policies via Open Policy Agent (OPA).
* **Certificate Hotswapping**: Reload certificates without restarting via
  SIGHUP/SIGUSR1 or timed reload intervals, enabling use of short-lived
  certificates.
* **Flexible Certificate Sources**: Load certificates and keys from PEM/PKCS#12
  files, ACME (Let's Encrypt), hardware security modules (PKCS#11), macOS
  Keychain, Windows Certificate Store, or the SPIFFE Workload API.
* **Secure by Default**: Listeners and targets are restricted to localhost and
  UNIX sockets unless explicitly overridden with `--unsafe-listen` or
  `--unsafe-target`, preventing accidental exposure. On Linux, Landlock
  sandboxing is enabled by default to limit process privileges.
* **Metrics & Profiling**: Built-in status port with JSON and Prometheus
  metrics endpoints, plus optional pprof profiling.

Ghostunnel also supports PROXY protocol v2, systemd/launchd socket activation,
and more. See the [documentation](docs/) for details.

## Getting Started

See the [Quick Start](/docs/quickstart/) guide for installation, generating
test certificates, and running your first tunnel. The full documentation is
available under [Docs](/docs/).

## Supported Platforms

Ghostunnel is developed primarily for Linux and macOS but runs on any UNIX
system with `SO_REUSEPORT` (FreeBSD, OpenBSD, NetBSD). Windows is also
supported, though without signal-based certificate reload (use
`--timed-reload`), syslog, Landlock sandboxing, or socket activation.

## License

Ghostunnel is licensed under the [Apache License 2.0](https://github.com/ghostunnel/ghostunnel/blob/master/LICENSE).
