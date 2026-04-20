---
title: Graceful Shutdown
description: How Ghostunnel handles shutdown signals, drains in-flight connections, and force-exits after a timeout.
weight: 87
---

Ghostunnel supports graceful shutdown: when a shutdown is triggered, it stops
accepting new connections and waits for existing connections to drain before
exiting. If connections do not drain within the configured timeout, the process
force-exits.

## Shutdown Triggers

There are three ways to initiate a graceful shutdown:

### Signals (Unix)

On Unix (Linux, macOS), sending `SIGTERM` or `SIGINT` to the Ghostunnel
process triggers a graceful shutdown:

```bash
# Graceful shutdown via signal
kill -TERM <pid>
kill -INT <pid>    # also sent by Ctrl+C
```

> **Note:** `SIGHUP` and `SIGUSR1` do *not* shut down the process. They
> trigger a reload of certificates and OPA policies instead.

### Signals (Windows)

On Windows, only the `Interrupt` signal (Ctrl+C) triggers shutdown. There are
no reload signals on Windows, but `--timed-reload` can be used to periodically
reload certificates and OPA policies on a fixed interval.

### HTTP endpoint (`/_shutdown`)

*Available since v1.8.1.*

If `--enable-shutdown` is set (requires `--status`), you can trigger a
shutdown via HTTP POST:

```bash
curl -X POST --cacert test-keys/cacert.pem https://localhost:6060/_shutdown
```

Any HTTP method other than POST returns 405 Method Not Allowed.

## Shutdown Sequence

When a shutdown is triggered, the following happens in order:

1. **Status transitions to "stopping"**: the `/_status` endpoint reflects
   that the process is shutting down.
2. **Status HTTP server begins shutting down**: best-effort graceful shutdown
   of the internal status listener.
3. **Force-exit timer starts**: a timer begins counting down from the
   `--shutdown-timeout` value (default: 5 minutes).
4. **Listener closes**: Ghostunnel stops accepting new connections.
5. **In-flight connections continue**: existing connections are not
   interrupted. Data continues to flow until both sides close normally.
6. **Process exits** when either:
   - All in-flight connections have drained (exit code 0), or
   - The shutdown timeout fires (exit code 1).

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--shutdown-timeout` | `5m` | Maximum time to wait for in-flight connections to drain. If connections are still open after this duration, the process force-exits with code 1. |
| `--enable-shutdown` | `false` | Enable the `/_shutdown` HTTP endpoint on the status port. Requires `--status`. |
| `--status` | *(none)* | HOST:PORT (or `unix:SOCKET`) for the status listener. Required for `/_shutdown`. |

See [Command-Line Flags]({{< ref "FLAGS.md" >}}) for the full flag reference.

## Choosing a Shutdown Timeout

The default timeout of 5 minutes is deliberately generous. Consider your
workload when tuning this value:

- **Short-lived requests** (e.g. REST APIs): a lower timeout like `30s` or
  `1m` is usually sufficient.
- **Long-lived connections** (e.g. streaming, WebSocket-like traffic): you may
  need to increase the timeout or accept that some connections will be
  force-closed.
- **Zero-downtime deployments**: coordinate the shutdown timeout with your
  orchestrator's termination grace period (e.g. Kubernetes
  `terminationGracePeriodSeconds`) to avoid the orchestrator killing the
  process before Ghostunnel's own timeout fires.

Other flags like `--connect-timeout` and `--max-conn-lifetime` also influence
connection behavior and may be relevant when tuning shutdown. See
[Command-Line Flags]({{< ref "FLAGS.md" >}}) for the full list.

## Integration with systemd

*Available since v1.8.0.*

When running as a systemd service with `Type=notify-reload`, Ghostunnel
notifies systemd of its state transitions (ready, reloading, stopping). The
graceful shutdown sequence integrates naturally with systemd's service
lifecycle. See [Systemd Watchdog]({{< ref "WATCHDOG.md" >}}) for unit file
examples and configuration details.
