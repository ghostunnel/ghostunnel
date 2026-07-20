#!/usr/bin/env python3

"""
End-to-end test for the connection-wide --idle-timeout.

While both directions of a proxied connection are open, --idle-timeout reaps the
connection only when NO data moves in either direction for the timeout. Any byte
transferred in either direction resets the clock for the whole connection -- idle
is a property of the connection, not a single direction.

Two phases, each on its own connection:

  (a) A fully idle connection: after exchanging data both peers go silent, and
      the client must observe EOF within a small multiple of --idle-timeout.

  (b) An asymmetric-but-active connection: the client stays silent while the
      backend trickles a chunk every ~1s for ~6s (3x --idle-timeout). Because
      the backend direction keeps moving, the connection-wide clock never
      expires and the (silent) client->backend direction is NOT reaped. This is
      the end-to-end guardrail for the connection-wide semantics: a per-direction
      idle deadline would reap the silent direction and tear down the connection
      mid-stream.

Like test-client-half-close-rolling-deadline.py, this uses client mode with a
plaintext local client on purpose: the reads of the returned bytes happen on a
plain socket, and ghostunnel's TLS side (the backend connection) is still
exercised.
"""

import time

from common import SocketPair, TcpClient, TlsServer, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_client, recv_exact

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_client(extra_args=['--idle-timeout=2s'])

    # (a) Fully idle connection is reaped after ~--idle-timeout of silence.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> server")
    pair.validate_can_send_from_server("hello world", "server -> client")

    print_ok("both peers go silent; expecting idle reap")
    pair.client.get_socket().settimeout(6)
    data = pair.client.get_socket().recv(16)
    if data != b'':
        raise Exception("expected EOF after idle reap, got {0!r}".format(data))
    print_ok("client observed EOF after idle reap")
    pair.client.get_socket().close()

    # (b) Active-but-asymmetric connection must NOT be reaped: the client is
    # silent while the backend trickles return traffic every ~1s for 6s == 3x
    # the 2s --idle-timeout. A per-direction idle deadline would reap the silent
    # client->backend direction; the connection-wide clock must keep it alive.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello world", "client -> server")

    print_ok("client goes silent; backend trickles return traffic past --idle-timeout")
    pair.client.get_socket().settimeout(6)
    for i in range(6):
        time.sleep(1)
        chunk = 'chunk{0}'.format(i).encode('utf-8')
        pair.server.get_socket().send(chunk)
        data = recv_exact(pair.client.get_socket(), len(chunk))
        if data != chunk:
            raise Exception("idle timeout cut off active return traffic at chunk {0}: got {1!r}, wanted {2!r}".format(i, data, chunk))
        print_ok("received return chunk {0} at ~{1}s (past --idle-timeout)".format(i, i + 1))

    pair.client.get_socket().close()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
