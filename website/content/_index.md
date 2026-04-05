---
title: Ghostunnel
description: A simple TLS proxy with mutual authentication support
---

Ghostunnel is a simple TLS proxy with mutual authentication support for
securing non-TLS backend applications. Ghostunnel supports two modes, **client
mode** and **server mode**. Ghostunnel in server mode runs in front of a
backend server and accepts TLS-secured connections, which are then proxied to
the (insecure) backend. Ghostunnel in client mode accepts (insecure)
connections through a TCP or UNIX domain socket and proxies them to a
TLS-secured service. A backend can be a TCP domain/port or a UNIX domain
socket.

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

Ghostunnel also supports UNIX domain sockets, PROXY protocol v2, systemd/launchd
socket activation, and more. See the [documentation](docs/) for details.

## Install

Pre-built binaries for Linux, macOS, and Windows are available under [Releases](/releases).

Via Homebrew:

```bash
brew install ghostunnel
```

Via Docker (see [Docker Hub](https://hub.docker.com/r/ghostunnel/ghostunnel) for all
available tags):

```bash
docker pull ghostunnel/ghostunnel:latest-distroless  # Distroless (recommended)
docker pull ghostunnel/ghostunnel:latest-alpine      # Alpine
docker pull ghostunnel/ghostunnel:latest-debian      # Debian
```

Compile from source (replace `VERSION` with a [release tag](https://github.com/ghostunnel/ghostunnel/releases)):

```bash
go install github.com/ghostunnel/ghostunnel@VERSION
```

## Usage

Start a Ghostunnel in server mode to proxy TLS connections to a backend:

```bash
ghostunnel server \
    --listen :8443 \
    --target localhost:8080 \
    --keystore server-keystore.p12 \
    --cacert cacert.pem \
    --allow-cn client
```

Start a Ghostunnel in client mode to wrap connections in TLS:

```bash
ghostunnel client \
    --listen localhost:8080 \
    --target example.com:8443 \
    --keystore client-combined.pem \
    --cacert cacert.pem
```

See [Docs](/docs) for more in-depth usage information.

## Supported Platforms

Ghostunnel is developed primarily for Linux and macOS, although it should run
on any UNIX system that exposes `SO_REUSEPORT`, including FreeBSD, OpenBSD and
NetBSD. Ghostunnel also supports running on Windows, though without
signal-based certificate reload (use `--timed-reload` instead), syslog output,
Landlock sandboxing, and socket activation.

## License

Ghostunnel is licensed under the [Apache License 2.0](https://github.com/ghostunnel/ghostunnel/blob/master/LICENSE).
