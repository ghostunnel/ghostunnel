#!/usr/bin/env python3

"""
Regression test for the rolling (inactivity-based) --close-timeout in the
untested direction and mode: server mode, the *backend* half-closes, and the
surviving direction is forward (TLS client -> backend).

test-client-half-close-rolling-deadline.py covers client mode with the return
direction surviving; this mirrors it for server mode with the forward direction
surviving. Here the survivor reads from a *tls.Conn (the client side), so the
reap ultimately closes a blocked TLS read -- a distinct code path from the
plaintext-survivor case.

Once one side half-closes, --close-timeout is an idle timeout on the surviving
direction: every transfer pushes the deadline forward, so an actively-flowing
forward stream is never cut off, and only genuine silence for --close-timeout
reaps it. The client sends a chunk every ~1s for 6s (3x the 2s --close-timeout);
under an absolute deadline the connection would die after 2s, so the backend
receiving all 6 proves the deadline rolls forward with forward traffic. Then the
client goes silent and the backend observes EOF, proving the idle reaper fires.

Why the plaintext backend initiates the half-close (as in the existing
half-close tests): Python's ssl module cannot half-close cleanly -- unwrap()
tears down the read side too -- so the plaintext side always does the
shutdown(SHUT_WR). Ghostunnel propagates it as CloseWrite (close_notify) on the
client *tls.Conn.

Constraint specific to this test: after the half-close, we never call recv on
the TLS client. The close_notify must stay unprocessed in the kernel buffer;
reading it makes Python's SSL object register the peer's shutdown and can make
subsequent send calls fail. Blocking-mode SSL_write does not process inbound
records, so send-only is safe. Every post-half-close assertion happens on the
plaintext backend side.
"""

import socket
import time

from common import (SocketPair, TlsClient, TcpServer, print_ok, terminate,
                    LISTEN_PORT, TARGET_PORT, create_default_certs,
                    start_ghostunnel_server, recv_exact, wait_for_metric,
                    get_metrics)

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server(extra_args=['--close-timeout=2s'])

    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> backend")
    pair.validate_can_send_from_server("hello world", "backend -> client")

    print_ok("half-closing backend write side")
    pair.server.get_socket().shutdown(socket.SHUT_WR)

    # Client dribbles a chunk every ~1s for 6s == 3x the 2s --close-timeout.
    # Under an absolute deadline the surviving forward direction would be reaped
    # after 2s; the rolling deadline must keep it alive for the whole stream.
    # Send-only on the TLS client (see docstring): all assertions are on the
    # plaintext backend.
    for i in range(6):
        time.sleep(1)
        chunk = 'chunk{0}'.format(i).encode('utf-8')
        pair.client.get_socket().send(chunk)
        data = recv_exact(pair.server.get_socket(), len(chunk))
        if data != chunk:
            raise Exception("rolling deadline cut off active forward traffic at chunk {0}: got {1!r}, wanted {2!r}".format(i, data, chunk))
        print_ok("backend received forward chunk {0} at ~{1}s (past --close-timeout)".format(i, i + 1))

    # Now the client goes silent: the idle reaper must eventually close the
    # surviving forward direction. The backend observes EOF within a generous
    # bound.
    print_ok("client goes silent; expecting rolling-window reap")
    pair.server.get_socket().settimeout(6)
    data = pair.server.get_socket().recv(16)
    if data != b'':
        raise Exception("expected EOF after close-timeout reap, got {0!r}".format(data))
    print_ok("survivor reaped after silence")

    # The reap is a counted policy close: conn.timeout bumps, conn.error stays 0,
    # conn.open returns to 0.
    wait_for_metric('ghostunnel.conn.timeout', lambda v: v == 1)
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    metrics = get_metrics()
    if metrics.get('ghostunnel.conn.error') != 0:
        raise Exception("expected conn.error == 0 after reap, got {0}".format(
            metrics.get('ghostunnel.conn.error')))
    print_ok("reap counted (timeout=1, error=0, open=0)")

    pair.client.get_socket().close()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
