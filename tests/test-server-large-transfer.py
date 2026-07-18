#!/usr/bin/env python3

"""
Verifies byte-perfect integrity of large transfers through the tunnel in
each direction, exercising the io.CopyBuffer path and buffer pool in
proxy/proxy.go under real volume.

Direction 1: a TLS client streams a large payload through the tunnel to an
echo backend while simultaneously reading back and hashing the echoed
stream, and half-closes its write side immediately after the last payload
byte — while most of the echo is still in flight. The tunnel must keep
draining the return direction after the half-close (proxy.go half-closes
tls.Conn via CloseWrite instead of hard-closing it): every echoed byte
must still arrive, followed by EOF. Direction 2: a "server push" backend
writes the payload to the client and half-closes; the client hashes what
it receives and verifies that EOF is forwarded.
"""

import hashlib
import itertools
import os
import select
import socket
import ssl
import time

from common import LISTEN_PORT, TIMEOUT, BackendServer, TlsClient, \
    create_default_certs, print_ok, start_ghostunnel_server, terminate, \
    wait_for_metric

PAYLOAD_SIZE = 64 * 1024 * 1024
SEND_CHUNK = 256 * 1024
RECV_CHUNK = 64 * 1024
# Individual operations should always make progress quickly, but give them
# a bit more slack than the default TIMEOUT under parallel test load.
BULK_TIMEOUT = max(TIMEOUT, 20)


def tls_duplex_pump(sock, payload=b'', chunk_sizes=None, recv_limit=None,
                    read_until_eof=False, half_close_after_send=False,
                    collect_buf=None, progress_timeout=BULK_TIMEOUT):
    """Full-duplex send+receive on one SSL socket from a single thread.

    Note: concurrent SSL_read/SSL_write on the same SSL object from two
    threads is not safe (it corrupts OpenSSL state and stalls or returns
    spurious EOF), so this pumps both directions with a non-blocking
    select loop instead of send/recv threads.

    Sends all of payload in chunks sized by the chunk_sizes iterator
    (default SEND_CHUNK), optionally half-closing the write side once done,
    while simultaneously receiving either exactly recv_limit bytes or until
    EOF. Received bytes are hashed (and appended to collect_buf if given).
    Returns (received_count, sha256_hexdigest, eof_seen). Raises
    TimeoutError if no forward progress happens for progress_timeout."""
    sock.setblocking(False)
    if chunk_sizes is None:
        chunk_sizes = itertools.repeat(SEND_CHUNK)
    view = memoryview(payload)
    total = len(payload)
    sent = 0
    pending = None
    half_closed = False
    digest = hashlib.sha256()
    rcvd = 0
    eof = False
    last_progress = time.monotonic()

    def recv_done():
        if eof:
            return True
        if read_until_eof:
            return False
        return recv_limit is None or rcvd >= recv_limit

    while True:
        if sent >= total and half_close_after_send and not half_closed:
            # Half-close via the base class: SSLSocket.shutdown() would set
            # _sslobj to None, silently downgrading later recv() calls to
            # raw (encrypted) socket reads. We only want the TCP FIN.
            socket.socket.shutdown(sock, socket.SHUT_WR)
            half_closed = True
        if sent >= total and recv_done():
            break
        progressed = False
        # Drain the receive side until it would block.
        if not recv_done():
            try:
                while not recv_done():
                    want = RECV_CHUNK
                    if recv_limit is not None:
                        want = min(want, recv_limit - rcvd)
                    data = sock.recv(want)
                    if data == b'':
                        eof = True
                        break
                    digest.update(data)
                    if collect_buf is not None:
                        collect_buf.extend(data)
                    rcvd += len(data)
                    progressed = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass  # no data available right now; wait for select() below
        # Push the send side until it would block.
        if sent < total:
            try:
                while sent < total:
                    if pending is None:
                        size = max(1, next(chunk_sizes))
                        pending = view[sent:sent + size]
                    n = sock.send(pending)
                    sent += n
                    pending = pending[n:] if n < len(pending) else None
                    progressed = True
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                pass  # send buffer full right now; wait for select() below
        if progressed:
            last_progress = time.monotonic()
            continue
        if time.monotonic() - last_progress > progress_timeout:
            raise TimeoutError(
                "no progress for {0}s (sent {1}/{2} bytes, received {3})".format(
                    progress_timeout, sent, total, rcvd))
        rlist = [sock] if not recv_done() else []
        wlist = [sock] if sent < total else []
        select.select(rlist, wlist, [], 0.5)
    return rcvd, digest.hexdigest(), eof


def check_transfer(name, count, received_hash, expected_hash, elapsed):
    if count != PAYLOAD_SIZE:
        raise Exception("{0}: expected {1} bytes, received {2}".format(
            name, PAYLOAD_SIZE, count))
    if received_hash != expected_hash:
        raise Exception("{0}: sha256 mismatch (payload corrupted)".format(name))
    print_ok("{0}: {1} MiB intact in {2:.1f}s ({3:.1f} MiB/s)".format(
        name, PAYLOAD_SIZE >> 20, elapsed, (PAYLOAD_SIZE >> 20) / elapsed))


ghostunnel = None
backend = None
try:
    root = create_default_certs()
    # After a half-close, the remaining in-flight return traffic drains
    # under the --close-timeout deadline (set by copyData's teardown).
    # The harness default of 1s is enough on an idle machine but a flake
    # risk for 64 MiB under parallel CI load, so give it real headroom.
    ghostunnel = start_ghostunnel_server(extra_args=['--close-timeout=10s'])

    # Deterministic payload: generated once, hashed once, reused everywhere.
    payload = os.urandom(PAYLOAD_SIZE)
    expected_hash = hashlib.sha256(payload).hexdigest()

    # Single backend for both directions, dispatching on connection order:
    # first connection echoes, second pushes PAYLOAD_SIZE bytes,
    # half-closes, then drains until the client closes.
    def push_handler(conn):
        view = memoryview(payload)
        for i in range(0, PAYLOAD_SIZE, SEND_CHUNK):
            conn.sendall(view[i:i + SEND_CHUNK])
        conn.shutdown(socket.SHUT_WR)
        # Drain until the client closes so the shutdown stays graceful.
        try:
            while conn.recv(RECV_CHUNK):
                pass
        except OSError:
            pass  # client may reset instead of closing cleanly; drain is best-effort

    conn_counter = itertools.count()

    def dispatch_handler(conn):
        if next(conn_counter) == 0:
            BackendServer.echo_handler(conn)
        else:
            push_handler(conn)

    backend = BackendServer(
        handler=dispatch_handler, conn_timeout=BULK_TIMEOUT).start()

    ############ Direction 1: client -> echo backend -> client ############

    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    sock = client.get_socket()

    # Half-close the write side immediately after the last payload byte,
    # while most of the echo is still in flight. The tunnel half-closes
    # tls.Conn (closeWrite -> CloseWrite, closeRead -> no-op) instead of
    # hard-closing it, so every in-flight echoed byte must still arrive.
    # This is the regression guard for that behavior: a hard close here
    # drops the tail of the echo stream.
    start = time.monotonic()
    count, received_hash, _ = tls_duplex_pump(
        sock, payload, recv_limit=PAYLOAD_SIZE, half_close_after_send=True)
    elapsed = time.monotonic() - start

    check_transfer("client->echo->client (half-closed mid-flight)", count,
                   received_hash, expected_hash, elapsed)

    # After the full echo, the backend sees our forwarded FIN, finishes,
    # and closes its side; EOF must come back through the tunnel.
    sock.settimeout(TIMEOUT)
    if sock.recv(RECV_CHUNK) != b'':
        raise Exception("expected EOF after half-closed echo stream")
    print_ok("in-flight echo drained after half-close, EOF forwarded")
    client.cleanup()

    if backend.handler_errors:
        raise Exception("echo backend handler errors: {0}".format(
            backend.handler_errors))

    ############ Direction 2: backend push -> client ############
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    sock = client.get_socket()
    sock.settimeout(BULK_TIMEOUT)

    # Receive-only direction: a plain blocking loop from one thread is safe.
    start = time.monotonic()
    digest = hashlib.sha256()
    count = 0
    while True:
        data = sock.recv(RECV_CHUNK)
        if not data:
            break
        digest.update(data)
        count += len(data)
    elapsed = time.monotonic() - start

    check_transfer("backend push->client", count, digest.hexdigest(),
                   expected_hash, elapsed)
    # EOF (backend half-close) must be forwarded through the tunnel
    if sock.recv(RECV_CHUNK) != b'':
        raise Exception("expected EOF after backend push stream ended")
    print_ok("EOF forwarded after backend push")
    client.cleanup()

    ############ Final checks ############
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open back to 0")

    if backend.handler_errors:
        raise Exception("backend handler errors: {0}".format(
            backend.handler_errors))
    if backend.accepted != 2:
        raise Exception("expected 2 accepted connections, got {0}".format(
            backend.accepted))

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
