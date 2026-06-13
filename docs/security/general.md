---
title: General Security
description: Landlock sandboxing, TLS protocol settings, cipher suites, address restrictions.
weight: 10
---

Ghostunnel's TLS settings, address restrictions, and Landlock sandboxing.

## TLS Settings

Ghostunnel enforces a minimum TLS version of TLS 1.2, and TLS 1.3 is supported
and will be negotiated when both sides support it. Earlier versions of TLS are
not supported.

### Cipher Suites

In TLS 1.3, cipher suite selection is handled by Go's [`crypto/tls`][crypto-tls]
and cannot be configured by the application. For TLS 1.2, the configured cipher
suites all use authenticated encryption (AEAD). Older CBC-mode ciphers are not
enabled.

### Post-Quantum Key Exchange

Since Go 1.24 and Ghostunnel v1.11.0, TLS handshakes negotiate the hybrid
post-quantum key exchange X25519MLKEM768 when both peers support it.
Ghostunnel inherits this behavior from Go's [`crypto/tls`][crypto-tls]
defaults; no configuration is required to enable it. To disable hybrid PQ key
exchange, set the environment variable `GODEBUG=tlsmlkem=0`. See Go's
[`CurvePreferences`][curve-prefs] documentation for the authoritative list of
currently-supported key exchanges and the `GODEBUG` knobs that control them.

### Client Authentication

In server mode, Ghostunnel requires and verifies client certificates by
default. This can be disabled with `--disable-authentication`, in which case no
client certificate is requested.

The status port (`--status`) is optional and does not require client
certificates. It is typically consumed by monitoring systems that may not
have client certs. Like other addresses, it defaults to localhost and is not
exposed to the network unless explicitly configured otherwise.

## Address Restrictions

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

### Restricting to specific local users

Binding to `localhost` (or `127.0.0.1` / `[::1]`) blocks the network, but on a
shared host any local user can still connect to the port. If you need to
restrict access to a specific UID (for example, only `root` may reach the
plaintext side of a tunnel), bind to a UNIX domain socket and use
filesystem permissions:

```bash
ghostunnel client \
    --listen=unix:/var/run/ghostunnel/client.sock \
    --target=backend.example.com:8443 \
    ...
```

Set the socket's owner and mode so only the intended user can `connect(2)` to
it. With socket activation, the service manager creates the socket and applies
the permissions for you; see [Systemd]({{< ref "systemd.md" >}}) and
[Launchd]({{< ref "launchd.md" >}}). Otherwise, ensure the socket's parent
directory is `chmod 0700` and `chown` it to the intended user, since the path
must be traversable to connect.

Firewall-based UID filtering exists but is fragile. On Linux, `iptables`
supports `-m owner --uid-owner` and `nftables` supports `skuid`. On macOS, `pf`
accepts `user =` rules, but Apple has formally stated that `pf` is not a stable
API; see [TN3165: Packet Filter is not API][tn3165]. Prefer UNIX socket
permissions, which are kernel-enforced via VFS and survive OS upgrades.

## Landlock sandboxing

*Available since v1.8.0. Enabled by default since v1.9.0.*

On Linux, Ghostunnel uses [Landlock][landlock] to restrict its own process
privileges after startup. Landlock is a kernel-level access control mechanism
that limits which files and network ports a process can access.

### How It Works

After parsing flags and loading certificates, Ghostunnel builds a minimal set
of Landlock rules based on the flags it was given:

- **File access**: Read-only access to files referenced by flags (certificates,
  CA bundles, OPA policy bundles) including their parent directories so file
  rotation works. Read-write access to a small set of system paths needed for
  syslog, temporary files, and Go runtime state.
- **Network access**: Bind access for listening ports and connect access for
  upstream targets, metrics endpoints, and other outbound destinations derived
  from the configured flags. DNS resolution is always allowed.

### Best-Effort Mode

Landlock is applied in best-effort mode. If the kernel does not support
Landlock (network rules require Linux 6.7+), Ghostunnel logs a warning and
continues without sandboxing.

### Disabling Landlock

*Available since v1.9.0.*

Landlock can be disabled with `--disable-landlock` if it causes issues with
your deployment. This is not recommended. Landlock is also automatically
disabled when PKCS#11 is in use, since PKCS#11 modules are opaque shared
libraries that may require access to arbitrary files and sockets.

[crypto-tls]: https://pkg.go.dev/crypto/tls
[curve-prefs]: https://pkg.go.dev/crypto/tls#Config.CurvePreferences
[landlock]: https://docs.kernel.org/userspace-api/landlock.html
[tn3165]: https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
