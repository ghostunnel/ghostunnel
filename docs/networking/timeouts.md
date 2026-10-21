---
title: Timeouts & Connection Lifecycle
description: How Ghostunnel bounds connection establishment, idle connections, and half-closed connections, and the flags that control each timeout.
weight: 25
since: v1.12.0
aliases:
  - /docs/timeouts/
---

Ghostunnel forwards raw TCP/UNIX-socket byte streams and has no visibility
into application-level requests, so all of its timeouts are based on
connection state and data movement.

A proxied connection goes through these stages:

1. **Setup**: the TLS handshake and the dial to the backend, limited by
   `--connect-timeout`.
2. **Open**: data flows both ways. `--idle-timeout`, if set, closes the
   connection when nothing moves for too long.
3. **Half-closed**: one side has finished sending. The other direction keeps
   flowing until it finishes or `--close-timeout` passes with no data.
4. **Closed**: both directions are done, or a timeout fired.

`--max-conn-lifetime`, if set, applies at every stage.

## Flags & Defaults

| Flag | Default | Description |
|------|---------|-------------|
| `--connect-timeout` | `10s` | Time allowed to set up a connection: the TLS handshake and the dial to the backend. Must not be zero. |
| `--idle-timeout` | `0s` (disabled) | Close a connection when no data moves in either direction for this long. |
| `--close-timeout` | `60s` | Close a half-closed connection after this long with no data transferred. Zero closes it immediately. |
| `--max-conn-lifetime` | `0s` (disabled) | Close a connection once it reaches this age, regardless of activity. |
| `--shutdown-timeout` | `5m` | Maximum time to wait for connections to drain on process shutdown. See [Graceful Shutdown]({{< ref "graceful-shutdown.md" >}}). |

See [Command-Line Flags]({{< ref "flags.md" >}}) for the full flag reference.

## Connection Setup (`--connect-timeout`)

In server mode, the incoming TLS handshake and the dial to the backend
together must finish within `--connect-timeout`. In client mode, the dial and
TLS handshake to the remote server must finish within it (including any
[outbound proxy](../outbound-proxy/) exchange).

Ghostunnel completes the TLS handshake up front rather than on first read, so
a client that connects but never presents a certificate is dropped when the
timeout expires instead of holding the connection open.

## Idle Connections (`--idle-timeout`)

While both directions are open, `--idle-timeout` closes a connection that has
had no data move in either direction for that long. Traffic in either
direction keeps the whole connection alive, so a long download where the
client sends nothing is not affected.

The default is `0` (disabled): an open connection with no traffic stays up
until `--max-conn-lifetime`, if set. Enable it to reclaim connections from
clients that disappeared without closing them, such as crashed hosts or
dropped NAT mappings.

## Half-Closed Connections (`--close-timeout`)

A TCP connection can be *half-closed*: one side signals that it will send no
more data but can still receive. Some protocols rely on this, for example a
client that sends its full request, half-closes, then reads the response.

Ghostunnel passes a half-close on to the other side: as a TCP `FIN` on
plaintext sockets, or as a TLS `close_notify` alert on TLS connections. Data
in the other direction keeps flowing.

`--close-timeout` closes the connection once no data has been transferred for
that long. Any data resets the timer, so a slow but active response is not cut
off. Without this timeout, a peer that never finishes its side could hold the
connection, and a `--max-concurrent-conns` slot, open forever. Setting
`--close-timeout` to zero closes the connection as soon as one side
half-closes.

In v1.11.x and earlier, `--close-timeout` was a fixed deadline counted from
the half-close, regardless of activity.

## Maximum Connection Lifetime (`--max-conn-lifetime`)

`--max-conn-lifetime` closes a connection once it reaches the given age after
the handshake, however active it is. It applies alongside the other timeouts;
whichever fires first closes the connection. The default is `0` (no limit).

Use it to force periodic reconnection, for example so that long-lived
connections pick up new certificates, are re-checked against access control,
or are rebalanced across backends.

## Observability

Connections closed by a timeout are logged with the reason (unless connection
logging is suppressed with `--quiet=conns` or `--quiet=all`):

```
# --close-timeout=60s
connection from 10.0.0.5:51234 closed by timeout: no activity for 1m0s after half-close
# --idle-timeout=10m
connection from 10.0.0.5:51236 closed by timeout: no activity for 10m0s
# --max-conn-lifetime
connection from 10.0.0.5:51238 closed by timeout: max connection lifetime reached
```

Two metrics track timeouts (see [Metrics & Profiling]({{< ref "metrics.md" >}})):

- `conn.timeout`: connections closed by `--idle-timeout`, `--close-timeout`,
  or `--max-conn-lifetime`. A zero `--close-timeout` is not counted.
- `accept.timeout`: incoming TLS handshakes (server mode) that did not finish
  within `--connect-timeout`. A dial that times out is counted under
  `accept.error` instead.

## Graceful Shutdown

Process shutdown does not cut established connections: they keep flowing,
still subject to the timeouts above, while `--shutdown-timeout` bounds how
long the process waits for them to drain. See
[Graceful Shutdown]({{< ref "graceful-shutdown.md" >}}).
