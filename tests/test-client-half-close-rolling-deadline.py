#!/usr/bin/env python3

"""
Regression test for the rolling (inactivity-based) --close-timeout.

Once one side half-closes, --close-timeout is an *idle* timeout on the surviving
direction: every read/write pushes the deadline forward, so an actively-flowing
return stream is never cut off, and only genuine silence for --close-timeout
reaps the connection. This is the end-to-end proof of that behavior.

The backend sends a chunk every ~1s for 6s (3x the 2s --close-timeout); under
the old absolute deadline the connection would have died after 2s, so receiving
all 6 chunks proves the deadline rolls forward with traffic. Then the backend
goes silent and the client must observe EOF within a generous bound, proving the
idle reaper still fires.

Like test-client-half-close-return-traffic.py, this uses client mode with a
plaintext local client on purpose: the half-close and the reads of the returned
bytes both happen on a plain socket. Python's ssl module cannot reliably decrypt
after a raw shutdown(SHUT_WR), so a TLS peer could not observe the returned
bytes -- but ghostunnel's TLS side (the backend connection) is still exercised,
because the plaintext half-close makes ghostunnel closeWrite() the backend
*tls.Conn.
"""

import socket
import time

from common import SocketPair, TcpClient, TlsServer, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_client, recv_exact

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_client(extra_args=['--close-timeout=2s'])

    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> server")
    pair.validate_can_send_from_server("hello world", "server -> client")

    print_ok("half-closing client write side")
    pair.client.get_socket().shutdown(socket.SHUT_WR)

    # Backend dribbles a chunk every ~1s for 6s == 3x the 2s --close-timeout.
    # Under the old absolute deadline the surviving direction would be reaped
    # after 2s; the rolling deadline must keep it alive for the whole stream.
    for i in range(6):
        time.sleep(1)
        chunk = 'chunk{0}'.format(i).encode('utf-8')
        pair.server.get_socket().send(chunk)
        data = recv_exact(pair.client.get_socket(), len(chunk))
        if data != chunk:
            raise Exception("rolling deadline cut off active return traffic at chunk {0}: got {1!r}, wanted {2!r}".format(i, data, chunk))
        print_ok("received return chunk {0} at ~{1}s (past --close-timeout)".format(i, i + 1))

    # Now the backend goes silent: the idle reaper must eventually close the
    # surviving direction. The client should observe EOF within a generous bound.
    print_ok("backend goes silent; expecting idle reap")
    pair.client.get_socket().settimeout(6)
    data = pair.client.get_socket().recv(16)
    if data != b'':
        raise Exception("expected EOF after idle reap, got {0!r}".format(data))

    pair.client.get_socket().close()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
