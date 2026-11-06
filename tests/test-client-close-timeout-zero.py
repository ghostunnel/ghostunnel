#!/usr/bin/env python3

"""
Pins the --close-timeout=0 flag contract: "Zero means immediate closure."

With --close-timeout=0, the watchdog closes the surviving direction of a
half-close immediately rather than after any residual window (unit:
TestZeroCloseTimeoutPromptClosure). That immediate close is the configured
teardown, not a timeout, so it must not count under conn.timeout. A zero
close-timeout must not affect fully-open connections -- only the survivor of
a half-close.

Client mode, plaintext local client + TLS backend, mirroring the other
half-close tests: the plaintext side initiates the half-close because Python's
ssl module cannot half-close cleanly (unwrap() tears down the read side too).
"""

import socket

from common import (SocketPair, TcpClient, TlsServer, print_ok, terminate,
                    LISTEN_PORT, TARGET_PORT, create_default_certs,
                    start_ghostunnel_client, wait_for_metric, get_metrics)

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_client(extra_args=['--close-timeout=0s'])

    # A zero close-timeout must not affect a fully-open connection.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> server")
    pair.validate_can_send_from_server("hello world", "server -> client")

    print_ok("half-closing client write side")
    pair.client.get_socket().shutdown(socket.SHUT_WR)

    # With --close-timeout=0 the survivor is closed immediately on half-close. EOF must arrive promptly (milliseconds); the 3s
    # bound is the "immediate" assertion -- any accidental default (60s) or
    # residual window would blow it. No sub-second bound (CI jitter).
    pair.client.get_socket().settimeout(3)
    data = pair.client.get_socket().recv(16)
    if data != b'':
        raise Exception("expected prompt EOF with --close-timeout=0, got {0!r}".format(data))
    print_ok("survivor closed immediately on half-close")

    # An immediate close is not a timeout: conn.timeout and conn.error stay 0,
    # conn.open returns to 0.
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    metrics = get_metrics()
    for name in ('ghostunnel.conn.timeout', 'ghostunnel.conn.error'):
        if metrics.get(name) != 0:
            raise Exception("expected {0} == 0 after immediate close, got {1}".format(
                name, metrics.get(name)))
    print_ok("immediate close not counted (timeout=0, error=0, open=0)")

    pair.client.get_socket().close()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
