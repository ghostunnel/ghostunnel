#!/usr/bin/env python3

"""
Verifies that byte-at-a-time and odd-sized writes survive the tunnel with
ordering intact (framing/short-read robustness), and that latency-sensitive
small-packet forwarding doesn't stall.

All phases run on a single TLS connection (with TCP_NODELAY) through
ghostunnel to an echo backend:
  1. a 4 KiB payload sent one byte at a time, echo compared byte-for-byte;
  2. a 256 KiB payload sent in awkward prime-ish chunk sizes cycling
     (1, 2, 3, 7, ...), echo verified via sha256;
  3. 200 iterations of send-1-byte / recv-1-byte ping-pong.
"""

import hashlib
import itertools
import os
import select
import socket
import ssl
import time

from common import LISTEN_PORT, TIMEOUT, BackendServer, TlsClient, \
    create_default_certs, print_ok, recv_exact, start_ghostunnel_server, \
    terminate, wait_for_metric

TINY_SIZE = 4096
ODD_TOTAL = 256 * 1024
ODD_SIZES = [1, 2, 3, 7, 13, 31, 61, 127, 251, 509, 1021, 2039]
PING_PONG_ITERATIONS = 200
SEND_CHUNK = 64 * 1024
RECV_CHUNK = 64 * 1024


def tls_duplex_pump(sock, payload=b'', chunk_sizes=None, recv_limit=None,
                    read_until_eof=False, half_close_after_send=False,
                    collect_buf=None, progress_timeout=TIMEOUT):
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


ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server()
    backend = BackendServer().start()  # default echo handler

    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    sock = client.get_socket()
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    ############ Phase 1: one byte at a time ############
    payload1 = os.urandom(TINY_SIZE)
    received = bytearray()
    start = time.monotonic()
    rcvd, _, _ = tls_duplex_pump(
        sock, payload1, chunk_sizes=itertools.repeat(1),
        recv_limit=TINY_SIZE, collect_buf=received)
    elapsed = time.monotonic() - start
    if rcvd != TINY_SIZE or bytes(received) != payload1:
        raise Exception("byte-at-a-time echo mismatch (bytes or order)")
    print_ok("phase 1: {0} single-byte writes echoed intact in {1:.1f}s".format(
        TINY_SIZE, elapsed))

    ############ Phase 2: awkward chunk sizes ############
    payload2 = os.urandom(ODD_TOTAL)
    expected_hash = hashlib.sha256(payload2).hexdigest()
    start = time.monotonic()
    rcvd, received_hash, _ = tls_duplex_pump(
        sock, payload2, chunk_sizes=itertools.cycle(ODD_SIZES),
        recv_limit=ODD_TOTAL)
    elapsed = time.monotonic() - start
    if rcvd != ODD_TOTAL:
        raise Exception("odd-chunk echo: expected {0} bytes, got {1}".format(
            ODD_TOTAL, rcvd))
    if received_hash != expected_hash:
        raise Exception("odd-chunk echo sha256 mismatch")
    print_ok("phase 2: {0} KiB in odd-sized chunks echoed intact in {1:.1f}s".format(
        ODD_TOTAL >> 10, elapsed))

    ############ Phase 3: 1-byte ping-pong ############
    # Sequential request/response, so plain blocking mode is safe here.
    sock.settimeout(TIMEOUT)
    start = time.monotonic()
    for i in range(PING_PONG_ITERATIONS):
        b = bytes([i % 256])
        sock.sendall(b)
        data = recv_exact(sock, 1)
        if data != b:
            raise Exception(
                "ping-pong iteration {0}: sent {1!r}, got {2!r}".format(
                    i, b, data))
    elapsed = time.monotonic() - start
    print_ok("phase 3: {0} 1-byte ping-pong round trips in {1:.2f}s".format(
        PING_PONG_ITERATIONS, elapsed))

    ############ Graceful shutdown + final checks ############
    # Half-close via the base class: SSLSocket.shutdown() would set _sslobj
    # to None, downgrading the recv() below to a raw (encrypted) read.
    socket.socket.shutdown(sock, socket.SHUT_WR)
    if sock.recv(1) != b'':
        raise Exception("expected EOF after half-close")
    client.cleanup()

    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open back to 0")

    if backend.handler_errors:
        raise Exception("backend handler errors: {0}".format(
            backend.handler_errors))
    if backend.accepted != 1:
        raise Exception("expected 1 accepted connection, got {0}".format(
            backend.accepted))

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
