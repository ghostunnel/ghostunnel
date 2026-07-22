---
title: Timeouts & Connection Lifecycle
description: How Ghostunnel bounds connection establishment, idle connections, and half-closed connections, and the flags that control each timeout.
weight: 20
aliases:
  - /docs/timeouts/
---

Ghostunnel forwards raw TCP/UNIX-socket byte streams and has no visibility
into application-level requests, so all of its timeouts are based on
connection state and data movement. This page explains the lifecycle of a
proxied connection, which timeout governs each phase, and how half-closed
connections are handled.

## Lifecycle of a Proxied Connection

Each accepted connection goes through the following phases:

1. **Establishment**: the TLS handshake with the client completes and the
   connection to the backend is dialed. Both are bounded by
   `--connect-timeout`.
2. **Open**: data flows in both directions. The connection stays open
   as long as data keeps moving. If `--idle-timeout` is set, the connection
   is closed once no data moves in *either* direction for that long.
3. **Half-closed**: one side has closed its sending direction (TCP `FIN` or
   TLS `close_notify`). Ghostunnel forwards the half-close to the other side
   and keeps proxying the surviving direction. The surviving direction is
   closed after `--close-timeout` passes with no data transferred.
4. **Closed**: both directions have finished (or a timeout fired), and both
   sockets are closed.

Independently of these phases, `--max-conn-lifetime` (if set) puts a hard cap
on the total lifetime of a connection, no matter how active it is.

## Flags & Defaults

| Flag | Default | Description |
|------|---------|-------------|
| `--connect-timeout` | `10s` | Timeout for establishing connections: covers the TLS handshake and dialing the backend. Must not be zero. |
| `--close-timeout` | `60s` | Inactivity timeout for half-closed connections: once one side terminates, the surviving direction is closed after this much time passes with no data transferred. Zero means immediate closure on half-close. |
| `--idle-timeout` | `0s` (disabled) | Close a connection when no data is transferred in either direction for this long, even while both directions are still open. Zero disables the idle timeout. |
| `--max-conn-lifetime` | `0s` (disabled) | Maximum lifetime for a connection after the handshake, regardless of activity. Zero means infinite. |
| `--shutdown-timeout` | `5m` | Maximum time to wait for connections to drain on process shutdown. See [Graceful Shutdown]({{< ref "graceful-shutdown.md" >}}). |

See [Command-Line Flags]({{< ref "flags.md" >}}) for the full flag reference.

## Connection Establishment

`--connect-timeout` bounds the establishment phase of every connection. In
server mode this covers the incoming TLS handshake and the dial to the
backend; in client mode it covers the TLS dial and handshake to the remote
server.

Ghostunnel forces the TLS handshake to complete within this window rather
than letting it happen lazily on first read. Without this, unauthenticated
clients could open connections and leave them hanging forever without ever
presenting a certificate.

A zero `--connect-timeout` is rejected at startup.

## Idle Connections (`--idle-timeout`)

*Available since v1.12.0.*

While both directions of a connection are open, `--idle-timeout` bounds how
long the connection may sit with no data moving at all. Any byte transferred
in *either* direction resets the clock for the whole connection.

Idle-ness is deliberately a property of the connection, not of a single
direction: an active but asymmetric transfer — say, a long download where the
client sends nothing — is never cut off mid-stream, because the download
traffic itself keeps resetting the clock.

The default is `0` (disabled), which preserves the historical behavior: a
fully-open connection with no traffic stays up indefinitely, bounded only by
`--max-conn-lifetime` if set. Enable an idle timeout if you want to reclaim
resources from abandoned connections, for example clients that disappeared
without a `FIN` (crashed hosts, dropped NAT mappings).

## Half-Close Handling (`--close-timeout`)

TCP connections can be *half-closed*: one side signals it will send no more
data (by sending a `FIN`) while still being able to receive. Some protocols
rely on this — a client sends its complete request, half-closes, and then
reads the full response.

Ghostunnel preserves half-close semantics where the underlying connections
allow it. When one copy direction finishes:

- On the **plaintext side** (TCP or UNIX socket), Ghostunnel uses the
  `shutdown()` system call to close only the relevant half: the read side of
  the source and the write side of the destination. The socket stays open for
  traffic in the other direction.
- On the **TLS side**, closing the write half sends a TLS `close_notify`
  alert without tearing down the underlying socket, so the opposite direction
  can keep flowing. The read half of a TLS connection cannot be shut down
  independently (Go's `tls.Conn` has no `CloseRead`), so it is simply left
  open until the whole connection closes.

Once a connection is half-closed, `--close-timeout` bounds how long the
surviving direction may stay silent: it is closed after `--close-timeout`
passes with no data transferred. This is an *inactivity* window, not a hard
deadline — every byte transferred resets it, so an active transfer is never
cut off no matter how long it takes. The timeout exists so that a peer that
never finishes its side cannot hold the connection (and a slot under
`--max-concurrent-conns`) open forever.

Setting `--close-timeout` to zero closes the connection immediately when
either side terminates, disabling half-close support entirely.

> **Note:** Prior to v1.12.0, `--close-timeout` was a fixed deadline: the
> surviving direction was closed `--close-timeout` after the half-close
> regardless of activity, which could cut off responses still in flight.
> Since v1.12.0 the window is rolling and only ever closes idle connections.

## Maximum Connection Lifetime (`--max-conn-lifetime`)

`--max-conn-lifetime` is a hard cap on the total lifetime of a connection
after the handshake. It applies in every phase and overrides the
activity-based timeouts: even a continuously active connection is closed once
it reaches this age. The default is `0` (no limit).

This is useful to force periodic reconnection, for example so that
long-lived connections eventually pick up new certificates, re-run access
control checks, or get rebalanced across backends.

## Which Timeout Applies When

At any moment, at most one activity-based window is armed, and
`--max-conn-lifetime` competes with it; whichever deadline comes first wins:

- **Both directions open**: `--idle-timeout` (if non-zero) counts down from
  the last transfer in either direction.
- **Half-closed**: `--close-timeout` takes over, counting down from the last
  transfer. The half-close itself counts as activity, so the surviving
  direction always gets a fresh window.
- **Any phase**: `--max-conn-lifetime` (if non-zero) reaps the connection at
  its fixed deadline if that comes sooner.

When a timeout fires, Ghostunnel closes both underlying connections. In-flight
reads and writes are unblocked and the connection is torn down.

## Observability

Connections closed by a timeout are logged with the reason (unless connection
logging is suppressed via `--quiet=conns` or `--quiet=all`):

```
connection closed by timeout: no activity for 1m0s after half-close
connection closed by timeout: no activity for 10m0s
connection closed by timeout: max connection lifetime reached
```

Two metrics track timeouts (see [Metrics & Profiling]({{< ref "metrics.md" >}})):

- `conn.timeout`: connections reaped by `--idle-timeout`,
  `--max-conn-lifetime`, or `--close-timeout` after a half-close.
- `accept.timeout`: TLS handshakes that timed out during `--connect-timeout`.

## Relationship to Graceful Shutdown

Process shutdown does not cut established connections: they continue to flow
and remain subject to the per-connection timeouts above, while
`--shutdown-timeout` bounds how long the process waits for them to drain. See
[Graceful Shutdown]({{< ref "graceful-shutdown.md" >}}) for details.
