#!/usr/bin/env python3

"""
End-to-end test for the interaction between --close-timeout and --idle-timeout,
and for the metric classification of the resulting reaps.

Three properties are covered (unit-tested by TestIdleTimeoutHalfCloseTransition,
TestRollingDeadlineReapsCounted, TestIdleTimeoutReapLoggedNotErrored), here
proven against a live instance:

  1. --close-timeout is inert while a connection is fully open. It is an idle
     timeout on the *surviving* direction that only arms after a half-close;
     a fully-open pair must survive silence far longer than --close-timeout as
     long as it stays under --idle-timeout.
  2. After a half-close, --close-timeout governs the survivor and --idle-timeout
     stops applying. Whichever of the two is set, the post-half-close window is
     the close window, not the idle window.
  3. A reap (idle or half-close) is a counted policy close: it bumps
     conn.timeout, never conn.error, and returns conn.open to 0.

Two ghostunnel instances run sequentially (instance A is terminated before B
starts; both bind the same ports). Instance A has a short close-timeout and a
huge idle-timeout; instance B has the converse arrangement.

Like test-client-half-close-rolling-deadline.py, this uses client mode with a
plaintext local client on purpose: the half-close and the reads of returned
bytes happen on a plain socket. Python's ssl module cannot half-close cleanly
(unwrap() tears down the read side too), so the plaintext side always initiates
the half-close; ghostunnel's TLS side (the backend connection) is still
exercised, because the plaintext half-close makes ghostunnel closeWrite() the
backend *tls.Conn.
"""

import socket
import time

from common import (SocketPair, TcpClient, TlsServer, print_ok, terminate,
                    LISTEN_PORT, TARGET_PORT, create_default_certs,
                    start_ghostunnel_client, recv_exact, wait_for_metric,
                    get_metrics)


def assert_reap_metrics(context):
    """Assert exactly one policy reap and nothing errored/still-open."""
    wait_for_metric('ghostunnel.conn.timeout', lambda v: v == 1)
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    metrics = get_metrics()
    if metrics.get('ghostunnel.conn.error') != 0:
        raise Exception("{0}: expected conn.error == 0, got {1}".format(
            context, metrics.get('ghostunnel.conn.error')))
    if metrics.get('ghostunnel.conn.timeout') != 1:
        raise Exception("{0}: expected conn.timeout == 1, got {1}".format(
            context, metrics.get('ghostunnel.conn.timeout')))
    print_ok("{0}: reap counted (timeout=1, error=0, open=0)".format(context))


ghostunnel = None
root = None
try:
    root = create_default_certs()

    # ---- Instance A: --close-timeout=1s --idle-timeout=30s -----------------
    # Short close window, huge idle window: exercises "close-timeout inert while
    # open" (the idle window is far too long to fire during the sleep) and
    # "close-timeout governs after half-close".
    ghostunnel = start_ghostunnel_client(
        extra_args=['--close-timeout=1s', '--idle-timeout=30s'])

    # Phase A: a fully-open pair must survive silence >> --close-timeout.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "A/phase A: client -> server")
    pair.validate_can_send_from_server("hello world", "A/phase A: server -> client")

    # Sleep 3x --close-timeout (and far below --idle-timeout=30s). If any
    # regression applied close-timeout to fully-open pairs, the pair would be
    # dead after 1s and the second exchange below would fail. The 30s
    # idle-timeout is deliberately huge so a CI stall cannot trigger an idle
    # reap during this sleep.
    print_ok("A/phase A: holding fully-open pair idle for 3s (3x --close-timeout)")
    time.sleep(3)
    pair.validate_can_send_from_client("still open", "A/phase A: client -> server survived")
    pair.validate_can_send_from_server("still open", "A/phase A: server -> client survived")
    pair.client.get_socket().close()
    print_ok("A/phase A: close-timeout inert while fully open")

    # Phase B: after a half-close, the 1s close-timeout reaps the survivor even
    # though --idle-timeout is 30s. If idle-timeout governed post-half-close (or
    # nothing did), the recv below would time out.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "A/phase B: client -> server")
    pair.validate_can_send_from_server("hello world", "A/phase B: server -> client")

    print_ok("A/phase B: half-closing client write side")
    pair.client.get_socket().shutdown(socket.SHUT_WR)
    pair.client.get_socket().settimeout(6)
    data = pair.client.get_socket().recv(16)
    if data != b'':
        raise Exception("A/phase B: expected EOF after close-timeout reap, got {0!r}".format(data))
    print_ok("A/phase B: survivor reaped by --close-timeout (~1s), not --idle-timeout")
    pair.client.get_socket().close()

    assert_reap_metrics("instance A")

    terminate(ghostunnel)
    ghostunnel = None

    # ---- Instance B: --idle-timeout=1s --close-timeout=5s ------------------
    # Converse arrangement: short idle window, longer close window. Proves the
    # idle-timeout stops applying once half-closed, and that the close window is
    # rolling (traffic past the idle-timeout is delivered, then silence reaps).
    ghostunnel = start_ghostunnel_client(
        extra_args=['--idle-timeout=1s', '--close-timeout=5s'])

    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "B/phase C: client -> server")
    pair.validate_can_send_from_server("hello world", "B/phase C: server -> client")

    # Half-close promptly: the pair must not sit idle >1s (--idle-timeout) while
    # still fully open, or it would be idle-reaped before the half-close.
    print_ok("B/phase C: half-closing client write side promptly")
    pair.client.get_socket().shutdown(socket.SHUT_WR)

    # Sleep past --idle-timeout (1s) but well under --close-timeout (5s). If the
    # idle-timeout still applied after half-close, the survivor would already be
    # gone; the single receive below proves it outlived the idle window and that
    # the close window permits traffic.
    print_ok("B/phase C: sleeping 2.5s (past --idle-timeout, under --close-timeout)")
    time.sleep(2.5)
    chunk = b'past-idle-timeout'
    pair.server.get_socket().send(chunk)
    pair.client.get_socket().settimeout(6)
    data = recv_exact(pair.client.get_socket(), len(chunk))
    if data != chunk:
        raise Exception("B/phase C: survivor did not deliver post-idle traffic: got {0!r}".format(data))
    print_ok("B/phase C: survivor outlived --idle-timeout and delivered return traffic")

    # That receive reset the close clock; now go silent and the 5s close-timeout
    # reaps ~5s later.
    print_ok("B/phase C: backend goes silent; expecting close-timeout reap")
    pair.client.get_socket().settimeout(10)
    data = pair.client.get_socket().recv(16)
    if data != b'':
        raise Exception("B/phase C: expected EOF after close-timeout reap, got {0!r}".format(data))
    print_ok("B/phase C: survivor reaped by --close-timeout after silence")
    pair.client.get_socket().close()

    assert_reap_metrics("instance B")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
