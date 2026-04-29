---
title: Command-Line Flags
description: Quick reference for all Ghostunnel command-line flags, grouped by mode.
weight: 20
aliases:
  - /docs/flags/
---

For detailed usage of specific features, see the linked documentation pages.

## Global Flags

These flags are available in both `server` and `client` modes.

### Certificate / Key

See [Certificate Formats]({{< ref "formats.md" >}}) for details on
supported file formats and chain ordering.

| Flag | Description |
|------|-------------|
| `--keystore PATH` | Path to keystore (combined PEM with cert/key, or PKCS12 keystore). |
| `--cert PATH` | Path to certificate (PEM with certificate chain). |
| `--key PATH` | Path to certificate private key (PEM with private key). |
| `--storepass PASS` | Password for keystore (if using PKCS12 keystore, optional). |
| `--cacert CACERT` | Path to CA bundle file (PEM/X509). Uses system trust store by default. |
| `--use-workload-api` | Certificate and root CAs are retrieved via the SPIFFE Workload API. See [SPIFFE]({{< ref "spiffe-workload-api.md" >}}). |
| `--use-workload-api-addr ADDR` | Retrieve certificates and root CAs via the SPIFFE Workload API at the specified address (implies `--use-workload-api`). See [SPIFFE]({{< ref "spiffe-workload-api.md" >}}). |

### Keychain

These flags are only available on platforms with keychain support.
See [Keychain]({{< ref "keychain.md" >}}).

| Flag | Description | Availability |
|------|-------------|--------------|
| `--keychain-identity NAME` | Use local keychain identity with given common name or serial number. | macOS, Windows |
| `--keychain-issuer NAME` | Use local keychain identity with given issuer common name. | macOS, Windows |
| `--keychain-require-token` | Require keychain identity to be from a physical token. | macOS only |

### PKCS#11

These flags require a build with CGO enabled.
See [HSM/PKCS#11]({{< ref "hsm-pkcs11.md" >}}).

| Flag | Description | Availability |
|------|-------------|--------------|
| `--pkcs11-module PATH` | Path to PKCS#11 module (`.so`) file. | Requires CGO |
| `--pkcs11-token-label LABEL` | Token label for slot/key in PKCS#11 module. | Requires CGO |
| `--pkcs11-pin PIN` | PIN code for slot/key in PKCS#11 module. | Requires CGO |

### Timeouts

| Flag | Default | Description |
|------|---------|-------------|
| `--timed-reload DURATION` | | Reload keystores every given interval, refresh listener/client on changes. |
| `--shutdown-timeout DURATION` | `5m` | Process shutdown timeout. Terminates after timeout even if connections are still open. |
| `--connect-timeout DURATION` | `10s` | Timeout for establishing connections and handshakes. |
| `--close-timeout DURATION` | `1s` | Timeout for closing connections when one side terminates. Zero means immediate closure. |
| `--max-conn-lifetime DURATION` | `0s` | Maximum lifetime for connections post handshake. Zero means infinite. |
| `--max-concurrent-conns N` | `0` | Maximum number of concurrent connections. Zero means infinite. |

### Metrics

See [Metrics]({{< ref "metrics.md" >}}).

| Flag | Default | Description |
|------|---------|-------------|
| `--metrics-graphite ADDR` | | Collect metrics and report to the given Graphite instance (raw TCP). |
| `--metrics-url URL` | | Collect metrics and POST them periodically to the given URL (HTTP/JSON). |
| `--metrics-prefix PREFIX` | `ghostunnel` | Prefix string for all reported metrics. |
| `--metrics-interval DURATION` | `30s` | Collect (and post/send) metrics every specified interval. |

### Status / Logging

See [Metrics & Profiling]({{< ref "metrics.md" >}}) for details on the status port,
metrics endpoints, and profiling.

| Flag | Description | Availability |
|------|-------------|--------------|
| `--status ADDR` | Enable `/_status` and `/_metrics` on given HOST:PORT (or `unix:SOCKET`). | All platforms |
| `--enable-pprof` | Enable `/debug/pprof` endpoints alongside `/_status` (for profiling). | All platforms |
| `--enable-shutdown` | Enable `/_shutdown` endpoint alongside `/_status` to allow terminating via HTTP POST. | All platforms |
| `--quiet` | Silence log messages. Values: `all`, `conns`, `conn-errs`, `handshake-errs`. Can be repeated. | All platforms |
| `--syslog` | Send logs to syslog instead of stdout. | Linux, macOS |
| `--eventlog` | Send logs to Windows Event Log instead of stdout. | Windows |
| `--skip-resolve` | Skip resolving target host on startup (useful to start before network is up). | All platforms |

### Landlock

See [Security & TLS Configuration]({{< ref "general.md" >}}) for details on
Landlock sandboxing.

| Flag | Description | Availability |
|------|-------------|--------------|
| `--disable-landlock` | Disable the best-effort Landlock sandboxing. Landlock is automatically disabled when PKCS#11 is used. | Linux only |

## Server Mode Flags

Flags specific to `ghostunnel server`.

### Required

See [Systemd]({{< ref "systemd.md" >}}) and [Launchd]({{< ref "launchd.md" >}})
for `systemd:NAME` and `launchd:NAME` addresses.

| Flag | Description |
|------|-------------|
| `--listen ADDR` | Address and port to listen on (`HOST:PORT`, `unix:PATH`, `systemd:NAME`, or `launchd:NAME`). |
| `--target ADDR` | Address to forward connections to (`HOST:PORT` or `unix:PATH`). |

### Proxying

See [PROXY Protocol]({{< ref "proxy-protocol.md" >}}) for details on modes and TLV extensions.

| Flag | Description |
|------|-------------|
| `--target-status URL` | Address to target for status checking downstream healthchecks. Defaults to TCP healthcheck if not passed. |
| `--proxy-protocol` | Enable PROXY protocol v2 with connection info only (equivalent to `--proxy-protocol-mode=conn`). |
| `--proxy-protocol-mode MODE` | PROXY protocol v2 mode: `conn`, `tls`, or `tls-full`. Mutually exclusive with `--proxy-protocol`. |
| `--unsafe-target` | Do not limit target to localhost, `127.0.0.1`, `[::1]`, or UNIX sockets. See [Security]({{< ref "general.md" >}}). |

### Access Control

See [Access Control Flags]({{< ref "access-flags.md" >}}).

| Flag | Description |
|------|-------------|
| `--allow-all` | Allow all clients, do not check client cert subject. |
| `--allow-cn CN` | Allow clients with given common name (repeatable). |
| `--allow-ou OU` | Allow clients with given organizational unit name (repeatable). |
| `--allow-dns DNS` | Allow clients with given DNS subject alternative name (repeatable). |
| `--allow-uri URI` | Allow clients with given URI subject alternative name (repeatable). |
| `--disable-authentication` | Disable client authentication, no client certificate will be required. |

### ACME (Server)

See [ACME Support]({{< ref "acme.md" >}}).

| Flag | Description |
|------|-------------|
| `--auto-acme-cert FQDN` | Automatically obtain a certificate via ACME for the specified FQDN. |
| `--auto-acme-email EMAIL` | Email address associated with all ACME requests. |
| `--auto-acme-agree-to-tos` | Agree to the Terms of Service of the ACME CA. |
| `--auto-acme-ca URL` | URL of the ACME CA. Defaults to Let's Encrypt if not specified. |
| `--auto-acme-testca URL` | URL of the ACME CA's test/staging environment. If set, `--auto-acme-ca` is ignored. |

### OPA Policy (Server)

See [Access Control Flags]({{< ref "access-flags.md" >}}) for OPA/Rego policy details.

| Flag | Description |
|------|-------------|
| `--allow-policy BUNDLE` | Location of an OPA policy bundle. Mutually exclusive with other access control flags. |
| `--allow-query QUERY` | Rego query to validate against the client certificate and the policy. Must be used with `--allow-policy`. |

## Client Mode Flags

Flags specific to `ghostunnel client`.

### Required

See [Systemd]({{< ref "systemd.md" >}}) and [Launchd]({{< ref "launchd.md" >}})
for `systemd:NAME` and `launchd:NAME` addresses.

| Flag | Description |
|------|-------------|
| `--listen ADDR` | Address and port to listen on (`HOST:PORT`, `unix:PATH`, `systemd:NAME`, or `launchd:NAME`). |
| `--target ADDR` | Address to forward connections to (must be `HOST:PORT`). |

### Connection

| Flag | Description |
|------|-------------|
| `--unsafe-listen` | Do not limit listen to localhost, `127.0.0.1`, `[::1]`, or UNIX sockets. See [Security]({{< ref "general.md" >}}). |
| `--override-server-name NAME` | Override the server name used for hostname verification. |
| `--proxy URL` | Connect to target over given proxy (HTTP CONNECT or SOCKS5). Must be a proxy URL. |
| `--disable-authentication` | Disable client authentication, no certificate will be provided to the server. |

### Server Verification

See [Access Control Flags]({{< ref "access-flags.md" >}}).

| Flag | Description |
|------|-------------|
| `--verify-cn CN` | Allow servers with given common name (repeatable). |
| `--verify-ou OU` | Allow servers with given organizational unit name (repeatable). |
| `--verify-dns DNS` | Allow servers with given DNS subject alternative name (repeatable). |
| `--verify-uri URI` | Allow servers with given URI subject alternative name (repeatable). |

### OPA Policy (Client)

See [Access Control Flags]({{< ref "access-flags.md" >}}) for OPA/Rego policy details.

| Flag | Description |
|------|-------------|
| `--verify-policy BUNDLE` | Location of an OPA policy bundle. |
| `--verify-query QUERY` | Rego query to evaluate against the server certificate and the policy. |

## Service Subcommands (Windows)

Manage Ghostunnel as a native Windows service via the Service Control Manager.
All `service` subcommands require **Administrator** privileges. See
[Windows Service]({{< ref "windows-service.md" >}}) for the full guide.

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `service install [--service-name NAME] -- ARGS...` | Install and start the service. Proxy arguments follow `--` (e.g. `-- server --listen :8443 --target localhost:8080`). |
| `service uninstall [--service-name NAME]` | Stop and remove the service. Refuses to remove services not installed by Ghostunnel. |
| `service start [--service-name NAME]` | Start an existing stopped service. |
| `service stop [--service-name NAME]` | Gracefully stop a running service. |
| `service status [--service-name NAME]` | Show the current service state. |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--service-name NAME` | `ghostunnel` | Name to use for the Windows service. May contain letters, digits, hyphens, underscores, and spaces (max 256 characters). |

To send service logs to the Windows Event Log instead of stdout, pass
`--eventlog` in the proxy arguments after `--`. See
[Status / Logging](#status--logging).

## Environment Variables

Several flags can also be set via environment variables.

| Variable | Flag |
|----------|------|
| `KEYSTORE_PATH` | `--keystore` |
| `CERT_PATH` | `--cert` |
| `KEY_PATH` | `--key` |
| `KEYSTORE_PASS` | `--storepass` |
| `CACERT_PATH` | `--cacert` |
| `SPIFFE_ENDPOINT_SOCKET` | `--use-workload-api-addr` |
| `PKCS11_MODULE` | `--pkcs11-module` |
| `PKCS11_TOKEN_LABEL` | `--pkcs11-token-label` |
| `PKCS11_PIN` | `--pkcs11-pin` |
