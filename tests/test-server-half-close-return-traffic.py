#!/usr/bin/env python3

"""
Regression test for TLS half-close return-traffic draining. After a TLS client
half-closes its write side, the backend must still be able to send return
traffic back for up to --close-timeout. Exercises the DELAYED return case:
the backend responds ~2s after the half-close, strictly after ghostunnel's
copyData defer (closeRead/closeWrite) has run.
"""

import socket
import time

from common import SocketPair, TcpServer, TlsClient, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_server

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server(extra_args=['--close-timeout=10s'])

    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
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
