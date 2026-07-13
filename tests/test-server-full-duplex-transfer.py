#!/usr/bin/env python3

"""
Streams large payloads in BOTH directions simultaneously through single
tunnel connections, verifying that the two copyData goroutines and the
shared buffer pool in proxy/proxy.go don't corrupt or interleave data.

Each connection: the TLS client sends N bytes while simultaneously
receiving N different bytes pushed by the backend; the backend handler
mirrors this with its own send/recv threads on the plain TCP side. Both
sides transmit from the start to create bidirectional pressure. Integrity
is verified with sha256 on both ends. Runs 3 connections sequentially,
then 2 in parallel to stress the shared buffer pool across connections.
"""

import hashlib
import itertools
import os
import select
import socket
import ssl
import threading
import time

from common import LISTEN_PORT, TIMEOUT, BackendServer, TlsClient, \
    create_default_certs, print_ok, start_ghostunnel_server, terminate, \
    wait_for_metric

N = 24 * 1024 * 1024  # bytes per direction per connection
SEND_CHUNK = 256 * 1024
RECV_CHUNK = 64 * 1024
BULK_TIMEOUT = max(TIMEOUT, 20)

# Deterministic per-direction payloads (same for every connection).
TO_BACKEND = os.urandom(N)
TO_CLIENT = os.urandom(N)
TO_BACKEND_HASH = hashlib.sha256(TO_BACKEND).hexdigest()
TO_CLIENT_HASH = hashlib.sha256(TO_CLIENT).hexdigest()

# Hashes of client->backend data as computed by the backend handler,
# collected here for out-of-band verification by the main thread.
backend_results = []


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
                pass
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
                pass
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


def recv_n_hash(conn, n):
    """Receive exactly n bytes from a plain socket, return sha256 hexdigest."""
    digest = hashlib.sha256()
    got = 0
    while got < n:
        data = conn.recv(min(RECV_CHUNK, n - got))
        if not data:
            raise Exception(
                "premature EOF after {0} of {1} bytes".format(got, n))
        digest.update(data)
        got += len(data)
    return digest.hexdigest()


def duplex_handler(conn):
    """Backend handler: send N bytes and receive N bytes concurrently.

    This is the plain TCP side of the tunnel, so send/recv threads are
    safe here (unlike on the SSL side)."""
    reader_result = []
    reader_errors = []

    def reader():
        try:
            reader_result.append(recv_n_hash(conn, N))
        except Exception as e:
            reader_errors.append(e)

    t = threading.Thread(target=reader)
    t.start()
    # Send from the very start, concurrently with the read.
    view = memoryview(TO_CLIENT)
    for i in range(0, N, SEND_CHUNK):
        conn.sendall(view[i:i + SEND_CHUNK])
    t.join()
    if reader_errors:
        raise reader_errors[0]
    backend_results.append(reader_result[0])
    # Wait for the client to close so our side shuts down gracefully.
    try:
        conn.recv(1)
    except OSError:
        pass


def run_client_connection(conn_id):
    """One full-duplex client connection; raises on any failure."""
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    sock = client.get_socket()

    start = time.monotonic()
    rcvd, received_hash, _ = tls_duplex_pump(sock, TO_BACKEND, recv_limit=N)
    elapsed = time.monotonic() - start

    if rcvd != N:
        raise Exception("connection {0}: expected {1} bytes, got {2}".format(
            conn_id, N, rcvd))
    if received_hash != TO_CLIENT_HASH:
        raise Exception(
            "connection {0}: backend->client sha256 mismatch".format(conn_id))
    client.cleanup()
    print_ok("connection {0}: {1} MiB each way in {2:.1f}s".format(
        conn_id, N >> 20, elapsed))


ghostunnel = None
backend = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server()
    backend = BackendServer(
        handler=duplex_handler, conn_timeout=BULK_TIMEOUT).start()

    # 3 sequential connections, fresh connection each time
    for conn_id in range(1, 4):
        run_client_connection(conn_id)

    # 2 connections in parallel to stress the shared buffer pool
    failures = []

    def parallel_client(conn_id):
        try:
            run_client_connection(conn_id)
        except Exception as e:
            failures.append("connection {0}: {1}".format(conn_id, e))

    threads = [
        threading.Thread(target=parallel_client, args=(conn_id,))
        for conn_id in (4, 5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if failures:
        raise Exception("parallel connections failed: {0}".format(failures))
    print_ok("parallel connections OK")

    # Backend handlers may still be hashing the last bytes after the client
    # side finishes; poll for all results with a deadline.
    deadline = time.time() + TIMEOUT
    while len(backend_results) < 5 and time.time() < deadline:
        time.sleep(0.05)
    if len(backend_results) != 5:
        raise Exception("expected 5 backend results, got {0}".format(
            len(backend_results)))
    for i, digest in enumerate(backend_results):
        if digest != TO_BACKEND_HASH:
            raise Exception(
                "backend result {0}: client->backend sha256 mismatch".format(i))
    print_ok("all 5 client->backend streams intact on backend side")

    if backend.handler_errors:
        raise Exception("backend handler errors: {0}".format(
            backend.handler_errors))
    if backend.accepted != 5:
        raise Exception("expected 5 accepted connections, got {0}".format(
            backend.accepted))

    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open back to 0")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
