---
title: Security & TLS Configuration
description: TLS protocol settings, cipher suites, address restrictions, and Landlock sandboxing.
weight: 15
---

## TLS protocol

### Protocol versions

Ghostunnel enforces a minimum TLS version of **TLS 1.2**. TLS 1.0 and 1.1 are
not supported. TLS 1.3 is supported and will be negotiated when both sides
support it.

### Cipher suites

The following cipher suites are enabled by default, in order of preference:

**AES-GCM:**
- `TLS_AES_128_GCM_SHA256` (TLS 1.3)
- `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_AES_256_GCM_SHA384` (TLS 1.3)
- `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`

**ChaCha20-Poly1305:**
- `TLS_CHACHA20_POLY1305_SHA256` (TLS 1.3)
- `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305`
- `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305`

All suites use authenticated encryption (AEAD). CBC-mode ciphers are not
enabled. ECDSA suites are listed before RSA to prefer ECDSA when both
certificate types are available.

In TLS 1.3, cipher suite selection is handled by Go's [`crypto/tls`][crypto-tls]
and cannot be configured by the application. The TLS 1.3 suites listed above are always
available when TLS 1.3 is negotiated. The configurable cipher suite list only
affects TLS 1.2 connections.

### Curve preferences

In server mode, key exchange prefers the following elliptic curves:

1. **X25519**: fast, constant-time, widely supported
2. **P-256 (secp256r1)**: hardware-accelerated on most platforms

### Client authentication

In server mode, Ghostunnel requires and verifies client certificates by
default (`RequireAndVerifyClientCert`). This can be disabled with
`--disable-authentication`, in which case no client certificate is requested.

The status port (`--status`) is optional and does not require client
certificates. It is typically consumed by monitoring systems that may not
have client certs. Like other addresses, it defaults to localhost and is not
exposed to the network unless explicitly configured otherwise.

## Address restrictions

Listen and target addresses are restricted to localhost and UNIX sockets by
default, to prevent accidental exposure of plaintext traffic.

### Server mode

The `--target` address must be one of:
- `localhost:PORT`
- `127.0.0.1:PORT`
- `[::1]:PORT`
- `unix:PATH`

To forward to a remote host, pass `--unsafe-target`. The connection between
Ghostunnel and the backend is unencrypted, so exposing it beyond localhost
risks leaking plaintext traffic.

### Client mode

The `--listen` address must be one of:
- `localhost:PORT`
- `127.0.0.1:PORT`
- `[::1]:PORT`
- `unix:PATH`
- `systemd:NAME`
- `launchd:NAME`

To accept connections from remote hosts, pass `--unsafe-listen`. The listen
side of client mode accepts plaintext connections, so exposing it beyond
localhost risks unauthorized access to the proxied service.

## Landlock sandboxing

On Linux, Ghostunnel uses [Landlock][landlock] to restrict its own process
privileges after startup. Landlock is a kernel-level access control mechanism
that limits which files and network ports a process can access.

### How it works

After parsing flags and loading certificates, Ghostunnel builds a minimal set
of Landlock rules based on the flags it was given:

- **File access**: Read-only access to certificate files, CA bundles, and OPA
  policy bundles (and their parent directories, to support file rotation).
  Read-write access to `/dev`, `/var/run`, `/tmp`, `/proc` for syslog and temp files.
- **Network access**: Bind access for `--listen` and `--status` ports. Connect
  access for `--target`, `--metrics-graphite`, `--metrics-url`, and SPIFFE
  Workload API ports. DNS (TCP/53) is always allowed.

### Best-effort mode

Landlock is applied in best-effort mode. If the kernel does not support
Landlock (network rules require Linux 6.7+), Ghostunnel logs a warning and
continues without sandboxing.

### Disabling Landlock

Landlock can be disabled with `--disable-landlock` if it causes issues with
your deployment. This is not recommended. Landlock is also automatically
disabled when PKCS#11 is in use, since PKCS#11 modules are opaque shared
libraries that may require access to arbitrary files and sockets.

[crypto-tls]: https://pkg.go.dev/crypto/tls
[landlock]: https://docs.kernel.org/userspace-api/landlock.html
