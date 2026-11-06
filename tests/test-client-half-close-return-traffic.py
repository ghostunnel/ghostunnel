#!/usr/bin/env python3

"""
Regression test for half-close return-traffic draining across a TLS connection.

When one side half-closes its write direction, ghostunnel must half-close (not
hard-close) the other side so return traffic can still flow. After the
half-close, --close-timeout is an idle timeout: the surviving direction stays
open as long as data keeps moving and is only reaped after --close-timeout of
inactivity. This exercises the DELAYED return case: the backend responds ~2s
after the half-close, strictly after ghostunnel's copyData teardown defer
(closeRead/closeWrite) has run.

This uses client mode with a plaintext local client on purpose: the half-close
and the read of the returned bytes both happen on a plain socket. Python's ssl
module cannot reliably decrypt on a socket after a raw shutdown(SHUT_WR), so a
TLS peer cannot observe the returned bytes even when they are delivered
correctly -- but ghostunnel's TLS side (the backend connection here) is still
exercised by the fix, because the plaintext half-close makes ghostunnel
closeWrite() the backend *tls.Conn.
"""

import socket
import time

from common import SocketPair, TcpClient, TlsServer, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_client

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_client(extra_args=['--close-timeout=10s'])

    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> server")
    pair.validate_can_send_from_server("hello world", "server -> client")

    print_ok("half-closing client write side")
    pair.client.get_socket().shutdown(socket.SHUT_WR)

    time.sleep(2)  # past copyData defer, well under --close-timeout

    print_ok("backend sends delayed return traffic")
    pair.server.get_socket().send(b'RETURN')

    data = pair.client.get_socket().recv(6)
    if data != b'RETURN':
        raise Exception("return traffic after half-close dropped/corrupted: got {0!r}, wanted b'RETURN'".format(data))

    pair.client.get_socket().close()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
