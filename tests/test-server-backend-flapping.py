#!/usr/bin/env python3

"""
Ensures that ghostunnel stays healthy when the backend misbehaves, and
recovers immediately once the backend stabilizes.

Phase A (backend down): with nothing listening on the target port, client
TLS handshakes succeed but the tunnel closes quickly when the backend dial
fails. Phase B (accept-then-RST backend): a backend that immediately resets
every connection (SO_LINGER 1,0 + close) must not harm ghostunnel; the
conn.open metric returns to zero. Phase C (recovery): after swapping in a
well-behaved echo backend, connections with echo roundtrips work
immediately, including ten consecutive successes. Throughout, the process
must stay alive, and the goroutine count must return near the baseline
captured at startup.
"""

from common import LOCALHOST, BackendServer, create_default_certs, \
    goroutine_count, print_ok, recv_exact, start_ghostunnel_server, terminate, \
    wait_for_metric, wait_for_status, LISTEN_PORT, TIMEOUT

import os
import socket
import ssl
import struct
import time

GOROUTINE_TOLERANCE = 10


def assert_alive(ghostunnel, label):
    if ghostunnel.poll() is not None:
        raise Exception('ghostunnel died during {0} (rc={1})'.format(
            label, ghostunnel.returncode))


def tls_connect():
    """Do a raw TLS handshake to ghostunnel, return the connected socket."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client.crt', 'client.key')
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(TIMEOUT)
    sock = ctx.wrap_socket(raw, server_hostname=LOCALHOST)
    sock.connect((LOCALHOST, LISTEN_PORT))
    return sock


def rst_handler(conn):
    """Backend handler that resets (RST) every connection immediately."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    conn.close()


def echo_roundtrip():
    """Fresh connection + echo roundtrip; raises on any failure."""
    sock = tls_connect()
    try:
        payload = os.urandom(1024)
        sock.sendall(payload)
        data = recv_exact(sock, 1024)
        if data != payload:
            raise Exception('echo mismatch')
    finally:
        sock.close()


ghostunnel = None
rst_backend = None
echo_backend = None
root = None
try:
    root = create_default_certs()

    # no backend initially; the target port has nothing listening
    ghostunnel = start_ghostunnel_server(extra_args=['--enable-pprof'])
    wait_for_status(lambda info: info.get('message') == 'listening')
    baseline = goroutine_count()
    print_ok('goroutine baseline: {0}'.format(baseline))

    # Phase A: backend down. The TLS handshake completes, but the tunnel
    # closes quickly because the backend dial fails.
    for _ in range(10):
        sock = tls_connect()
        try:
            data = sock.recv(1)
            if data != b'':
                raise Exception('unexpected data with no backend: {0!r}'.format(data))
        except TimeoutError:
            # a recv timeout means the tunnel left the connection dangling
            # after the failed backend dial instead of closing it
            raise Exception('tunnel did not close connection with no backend')
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError):
            pass  # abrupt closure is also an acceptable way to end the tunnel
        finally:
            sock.close()
    assert_alive(ghostunnel, 'phase A (backend down)')
    print_ok('phase A: 10 handshakes with no backend, tunnel closed each time')

    # Phase B: backend accepts then immediately resets (RST) every conn.
    rst_backend = BackendServer(handler=rst_handler).start()
    for _ in range(20):
        sock = tls_connect()
        try:
            sock.sendall(b'x' * 1024)
            data = sock.recv(4096)
            if data != b'':
                raise Exception('unexpected data from RST backend: {0!r}'.format(data))
        except TimeoutError:
            # a recv timeout means the backend RST was not propagated and
            # the tunnel left the connection dangling
            raise Exception('tunnel did not propagate backend RST')
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError):
            pass  # abrupt closure expected
        finally:
            sock.close()
    assert_alive(ghostunnel, 'phase B (RST backend)')
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok('phase B: 20 connections through RST backend, conn.open back to 0')

    # Phase C: recovery with a well-behaved echo backend. stop() joins the
    # accept thread, so the RST listener is fully gone before the echo
    # backend binds the same port (no SO_REUSEPORT connection stealing).
    rst_backend.stop()
    rst_backend = None
    echo_backend = BackendServer().start()

    # first connection should work right away (retry against timing noise)
    deadline = time.time() + TIMEOUT
    while True:
        try:
            echo_roundtrip()
            break
        except Exception as e:
            if time.time() > deadline:
                raise
            print('recovery attempt failed ({0}), retrying...'.format(e))
            time.sleep(0.2)
    print_ok('phase C: first connection after recovery works')

    # then ten consecutive successful roundtrip connections
    for _ in range(10):
        echo_roundtrip()
    assert_alive(ghostunnel, 'phase C (recovery)')
    print_ok('phase C: 10 consecutive successful roundtrip connections')

    # goroutine count must settle back near the baseline (tolerate
    # transient status-port fetch failures while polling)
    deadline = time.time() + 3 * TIMEOUT
    count = None
    while time.time() < deadline:
        try:
            count = goroutine_count()
        except Exception as e:
            print('goroutine fetch failed ({0}), retrying...'.format(e))
            time.sleep(0.5)
            continue
        if count <= baseline + GOROUTINE_TOLERANCE:
            break
        time.sleep(0.5)
    if count is None or count > baseline + GOROUTINE_TOLERANCE:
        raise Exception('goroutine count did not settle: baseline={0}, '
                        'final={1}'.format(baseline, count))
    print_ok('goroutines settled: baseline={0}, final={1}'.format(baseline, count))

    assert_alive(ghostunnel, 'final check')
    print_ok('OK')
finally:
    terminate(ghostunnel)
    if rst_backend:
        rst_backend.stop()
    if echo_backend:
        echo_backend.stop()
    if root:
        root.cleanup()
