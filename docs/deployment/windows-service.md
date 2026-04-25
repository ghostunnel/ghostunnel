---
title: Windows Service
description: Install and manage Ghostunnel as a native Windows service via the Service Control Manager.
weight: 25
---

*Available since v1.11.0.*

Ghostunnel can run as a native Windows service managed by the
[Service Control Manager][scm] (SCM). The `ghostunnel service` subcommands
handle installation, removal, and lifecycle control. All service management
commands require **Administrator** privileges.

## Installing a Service

Use `ghostunnel service install` to register Ghostunnel with the SCM. Proxy
arguments (server or client mode flags) are passed after a `--` separator:

```bat
ghostunnel service install -- server ^
    --listen localhost:8443 ^
    --target localhost:8080 ^
    --cert C:\certs\server-cert.pem ^
    --key C:\certs\server-key.pem ^
    --cacert C:\certs\cacert.pem ^
    --allow-cn client
```

This registers the service, sets it to start automatically on boot, and
immediately starts it. The service appears in the SCM with the display name
"Ghostunnel (`<name>`)".

### Custom Service Name

By default the service is named `ghostunnel`. Use `--service-name` to run
multiple instances with different configurations:

```bat
ghostunnel service install --service-name ghostunnel-api -- server ^
    --listen localhost:8443 --target localhost:8080 ...

ghostunnel service install --service-name ghostunnel-admin -- server ^
    --listen localhost:9443 --target localhost:9080 ...
```

Service names may contain letters, digits, hyphens, underscores, and spaces
(max 256 characters).

## Managing a Service

```bat
# Check service status
ghostunnel service status [--service-name NAME]

# Start a stopped service
ghostunnel service start [--service-name NAME]

# Stop a running service (graceful drain)
ghostunnel service stop [--service-name NAME]

# Remove the service entirely
ghostunnel service uninstall [--service-name NAME]
```

Stopping a service triggers a graceful shutdown: Ghostunnel stops accepting
new connections and drains in-flight requests before exiting, the same as
sending `Ctrl-C` to an interactive process.

Uninstall will refuse to remove a service that was not originally installed
by Ghostunnel (identified by a `GhostunnelManaged` registry marker).

## Windows Event Log

When running as a service, you typically want logs written to the
[Windows Event Log][eventlog] rather than stdout. Pass `--eventlog` in the
proxy arguments:

```bat
ghostunnel service install -- server --eventlog ^
    --listen localhost:8443 --target localhost:8080 ...
```

Events are written under the source name matching the service name (default
`ghostunnel`). View them with Event Viewer or PowerShell:

```powershell
Get-EventLog -LogName Application -Source ghostunnel -Newest 20
```

The `--eventlog` flag also works when running Ghostunnel interactively
(outside of a service), though this is less common.

## Subcommand Reference

| Subcommand | Description |
|------------|-------------|
| `service install [--service-name NAME] -- ARGS...` | Register, configure, and start the service |
| `service uninstall [--service-name NAME]` | Stop and remove the service |
| `service start [--service-name NAME]` | Start an existing stopped service |
| `service stop [--service-name NAME]` | Gracefully stop a running service |
| `service status [--service-name NAME]` | Show the current service state |

All subcommands default to `--service-name ghostunnel` if not specified.

[scm]: https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager
[eventlog]: https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging
