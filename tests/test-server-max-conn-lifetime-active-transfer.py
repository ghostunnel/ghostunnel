#!/usr/bin/env python3

"""
End-to-end test that --max-conn-lifetime cuts off an *active* transfer.

--max-conn-lifetime is the one policy that ignores activity: unlike idle- and
close-timeout, it is a hard cap that fires even while data is flowing. The
existing lifetime tests (test-server-max-conn-lifetime.py) only reap idle
connections, so they cannot distinguish "lifetime cap" from "idle reap". This
test keeps the connection busy for its entire life and proves the cap still
fires (unit: Test*ClampedByMaxConnLifetime).

Server mode, TLS client + plaintext backend. A round trip runs every ~200ms;
somewhere before the generous upper bound the reap must interrupt the transfer,
surfacing as a ConnectionError / ssl.SSLError / EOF in the copy loop.

The conn.error == 0 assertion is load-bearing: reaping mid-transfer surfaces in
ghostunnel's copy goroutines as net.ErrClosed / EPIPE, which
isClosedConnectionError must classify as a silent close (a counted policy reap
under conn.timeout), not a copy error.
"""

import ssl
import time

from common import (SocketPair, TlsClient, TcpServer, print_ok, terminate,
                    LISTEN_PORT, TARGET_PORT, create_default_certs,
                    start_ghostunnel_server, recv_exact, wait_for_metric,
                    get_metrics)


class Mismatch(Exception):
    """Echo payload came back wrong -- a real failure, not a reap."""


ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server(extra_args=['--max-conn-lifetime=3s'])

    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> backend")
    pair.validate_can_send_from_server("hello world", "backend -> client")

    client_sock = pair.client.get_socket()
    backend_sock = pair.server.get_socket()
    # Short per-op timeouts: a healthy round trip completes in milliseconds, so
    # a timeout here means the connection is dead (which is what we're waiting
    # for), not a stall on a live connection.
    client_sock.settimeout(2)
    backend_sock.settimeout(2)

    # Keep the connection continuously busy. With --max-conn-lifetime=3s the
    # reap must interrupt this loop; if activity kept the connection alive past
    # the cap, the loop would run to the 12s guard and we would fail below.
    start = time.time()
    reaped = False
    round_trips = 0
    elapsed_at_cut = None
    msg = b'ping'
    while time.time() - start < 12:
        try:
            client_sock.sendall(msg)
            got = recv_exact(backend_sock, len(msg))
            backend_sock.sendall(got)
            echo = recv_exact(client_sock, len(msg))
            if echo != msg:
                raise Mismatch("echo mismatch: got {0!r}".format(echo))
            round_trips += 1
            time.sleep(0.2)
        except Mismatch:
            raise
        except Exception as e:
            elapsed_at_cut = time.time() - start
            reaped = True
            print_ok("active transfer cut off after ~{0:.1f}s / {1} round trips: {2!r}".format(
                elapsed_at_cut, round_trips, e))
            break

    if not reaped:
        raise Exception(
            "active transfer survived to 12s ({0} round trips): "
            "--max-conn-lifetime failed to cap an active connection".format(round_trips))
    # Generous upper bound vs. the 3s lifetime -- the exact regression this test
    # exists to catch is "activity kept it alive", already covered by `reaped`;
    # this guards against an absurdly late cut.
    if elapsed_at_cut > 10:
        raise Exception("reap arrived too late: {0:.1f}s (lifetime is 3s)".format(elapsed_at_cut))
    # Loose lower bound: a handful of round trips must have completed, proving
    # the transfer was genuinely active when reaped. No tight elapsed ~= 3s
    # assertion (CI jitter).
    if elapsed_at_cut < 1 or round_trips < 3:
        raise Exception("reap arrived implausibly early: {0:.1f}s, {1} round trips".format(
            elapsed_at_cut, round_trips))

    # A mid-transfer reap is a counted policy close: conn.timeout bumps,
    # conn.error stays 0 (net.ErrClosed/EPIPE classified silent), conn.open
    # returns to 0.
    wait_for_metric('ghostunnel.conn.timeout', lambda v: v == 1)
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    metrics = get_metrics()
    if metrics.get('ghostunnel.conn.error') != 0:
        raise Exception("expected conn.error == 0 after mid-transfer reap, got {0}".format(
            metrics.get('ghostunnel.conn.error')))
    print_ok("mid-transfer reap counted (timeout=1, error=0, open=0)")

    # A clean, short-lived connection must work and must NOT bump conn.timeout.
    healthy = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    healthy.validate_can_send_from_client("healthy", "healthy: client -> backend")
    healthy.validate_can_send_from_server("healthy", "healthy: backend -> client")
    healthy.client.get_socket().close()
    healthy.server.get_socket().close()
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    metrics = get_metrics()
    if metrics.get('ghostunnel.conn.timeout') != 1:
        raise Exception("clean close bumped conn.timeout: expected 1, got {0}".format(
            metrics.get('ghostunnel.conn.timeout')))
    print_ok("clean close left conn.timeout at 1")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
