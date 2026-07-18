#!/usr/bin/env python3

"""
Verifies that abortive closes (TCP RST via SO_LINGER(1,0)) mid-transfer,
from either the client side or the backend side, do not leak connections
in ghostunnel: conn.open must return to zero and the tunnel must still
serve normal connections afterwards.
"""

from common import BackendServer, LOCALHOST, LISTEN_PORT, \
    TcpClient, STATUS_PORT, create_default_certs, print_ok, recv_exact, \
    start_ghostunnel_server, terminate, wait_for_metric, TIMEOUT, _poll_sleep
import socket
import ssl
import struct
import time

ITERATIONS = 40


def command_handler(conn):
    """Backend handler: the first byte of client data is a command.

    b'E': echo everything after the command byte until EOF (normal path).
    b'R': read the rest of the first chunk, send a 1-byte ack, then RST
          the connection towards the tunnel via SO_LINGER(1,0)."""
    data = conn.recv(1 << 16)
    if not data:
        return
    cmd, rest = data[:1], data[1:]
    if cmd == b'R':
        # Ack so the client knows the backend received its data before
        # the RST is generated (avoids racing send with reset).
        conn.sendall(b'A')
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 0))
        conn.close()
        return
    # echo mode: echo the remainder of the first chunk, then keep echoing
    if rest:
        conn.sendall(rest)
    while True:
        data = conn.recv(1 << 16)
        if not data:
            break
        conn.sendall(data)


def make_client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client.crt', 'client.key')
    return ctx


def tls_connect(ctx, attempts=3):
    last = None
    for i in range(attempts):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        tls_sock = ctx.wrap_socket(sock, server_hostname=LOCALHOST)
        try:
            tls_sock.connect((LOCALHOST, LISTEN_PORT))
            return tls_sock
        except Exception as e:
            last = e
            try:
                tls_sock.close()
            except OSError:
                pass  # cleanup of a failed connect attempt, socket state unknown
            _poll_sleep(i)
    raise Exception("connect failed after {0} attempts: {1}".format(
        attempts, last))


def normal_echo_conn(ctx, payload):
    """Full clean roundtrip: connect, echo, close."""
    tls_sock = tls_connect(ctx)
    try:
        tls_sock.sendall(b'E' + payload)
        data = recv_exact(tls_sock, len(payload))
        if data != payload:
            raise Exception("echo mismatch: sent {0!r}, got {1!r}".format(
                payload, data))
    finally:
        tls_sock.close()


def client_side_rst(ctx, i):
    """Client sends data, verifies partial echo, then RSTs the tunnel."""
    tls_sock = tls_connect(ctx)
    payload = 'client-rst-{0}'.format(i).encode()
    tls_sock.sendall(b'E' + payload)
    data = recv_exact(tls_sock, len(payload))
    if data != payload:
        raise Exception("echo mismatch before client RST: {0!r}".format(data))
    # SO_LINGER(1, 0) + close() sends RST instead of FIN. setsockopt on
    # the ssl-wrapped socket proxies to the underlying socket.
    tls_sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 0))
    tls_sock.close()


def backend_side_rst(ctx, i):
    """Backend reads client data, then RSTs; client must observe the
    connection going away (reset, TLS error, or EOF)."""
    tls_sock = tls_connect(ctx)
    try:
        tls_sock.sendall(b'R' + 'backend-rst-{0}'.format(i).encode())
        ack = recv_exact(tls_sock, 1)
        if ack != b'A':
            raise Exception("unexpected ack before backend RST: {0!r}".format(ack))
        # Now the backend RSTs. The tunnel should tear the connection
        # down; further reads must fail or hit EOF (not hang past the
        # socket timeout).
        try:
            data = tls_sock.recv(1)
            if data:
                raise Exception(
                    "unexpected data after backend RST: {0!r}".format(data))
            # empty read = clean EOF propagated by the tunnel, acceptable
        except TimeoutError:
            # a recv timeout means the tunnel left the connection dangling
            # instead of propagating the RST — exactly the failure this
            # test exists to catch (TimeoutError is an OSError subclass,
            # so it must be handled before the catch-all below)
            raise Exception(
                "tunnel did not propagate backend RST within timeout")
        except (ConnectionError, ssl.SSLError, OSError):
            pass  # reset/TLS error propagated by the tunnel, acceptable
    finally:
        try:
            tls_sock.close()
        except OSError:
            pass  # close-time errors are expected after an abortive reset


ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()

    backend = BackendServer(handler=command_handler).start()
    ghostunnel = start_ghostunnel_server(extra_args=['--close-timeout=1s'])

    # wait for startup and do a warm-up connection
    TcpClient(STATUS_PORT).connect(20)
    ctx = make_client_context()
    warmup = tls_connect(ctx, attempts=20)
    warmup.sendall(b'Ewarmup')
    if recv_exact(warmup, len(b'warmup')) != b'warmup':
        raise Exception("warm-up echo mismatch")
    warmup.close()
    print_ok("warm-up connection OK")

    start = time.time()
    for i in range(ITERATIONS):
        if i % 2 == 0:
            client_side_rst(ctx, i)
        else:
            backend_side_rst(ctx, i)
    print_ok("completed {0} abortive-close iterations in {1:.1f}s".format(
        ITERATIONS, time.time() - start))

    # no connection may be left open on either RST path
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open returned to 0")

    # tunnel must still work normally after all the abuse
    normal_echo_conn(ctx, b'still-alive')
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("normal connection works after abortive closes")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
