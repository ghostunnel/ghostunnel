#!/usr/bin/env python3

"""
Stresses the --max-concurrent-conns semaphore with connection churn under
contention, including abnormal connection exits (abrupt closes without TLS
close_notify, and abandoned TCP connections that never complete a TLS
handshake). Afterwards verifies that no semaphore slot was leaked by
opening exactly max-concurrent-conns simultaneous working connections.
"""

from common import BackendServer, LOCALHOST, LISTEN_PORT, \
    TcpClient, STATUS_PORT, create_default_certs, print_ok, recv_exact, \
    start_ghostunnel_server, terminate, wait_for_metric, TIMEOUT, _poll_sleep
import socket
import ssl
import struct
import threading
import time

MAX_CONCURRENT = 4
NUM_THREADS = 12
ITERS_PER_THREAD = 30
CONNECT_ATTEMPTS = 8

# Sockets abandoned mid-handshake, closed at the very end of the test.
abandoned = []
abandoned_lock = threading.Lock()


def make_client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client.crt', 'client.key')
    return ctx


def tls_connect(ctx, attempts=CONNECT_ATTEMPTS):
    """Connect through the tunnel with generous retries: with only
    MAX_CONCURRENT semaphore slots and NUM_THREADS competing threads, a
    handshake may have to wait for a slot to free up (or may get cut off
    if we lose a race with connect-timeout reaping)."""
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
                pass
            _poll_sleep(i)
    raise Exception("connect failed after {0} attempts: {1}".format(
        attempts, last))


def echo_roundtrip(tls_sock, payload):
    tls_sock.sendall(payload)
    data = recv_exact(tls_sock, len(payload))
    if data != payload:
        raise Exception("echo mismatch: sent {0!r}, got {1!r}".format(
            payload, data))


def churn_worker(thread_id, results):
    ctx = make_client_context()
    ok = 0
    try:
        for i in range(ITERS_PER_THREAD):
            if thread_id % 3 == 0 and i % 15 == 5:
                # Occasionally open a TCP connection that never completes
                # a TLS handshake and abandon it. It occupies a semaphore
                # slot until --connect-timeout reaps it; the slot must
                # come back.
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(TIMEOUT)
                sock.connect((LOCALHOST, LISTEN_PORT))
                with abandoned_lock:
                    abandoned.append(sock)

            tls_sock = tls_connect(ctx)
            try:
                payload = 'sem-{0}-{1}'.format(thread_id, i).encode()
                echo_roundtrip(tls_sock, payload)
                if i % 5 == 2:
                    # Abrupt exit: RST the connection without sending a
                    # TLS close_notify.
                    tls_sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_LINGER,
                        struct.pack('ii', 1, 0))
            finally:
                tls_sock.close()
            ok += 1
    except Exception as e:
        results[thread_id] = (ok, e)
        return
    results[thread_id] = (ok, None)


ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()

    backend = BackendServer().start()
    ghostunnel = start_ghostunnel_server(
        extra_args=['--max-concurrent-conns={0}'.format(MAX_CONCURRENT),
                    '--connect-timeout=2s'])

    # wait for startup and do a warm-up connection
    TcpClient(STATUS_PORT).connect(20)
    warmup_ctx = make_client_context()
    warmup = tls_connect(warmup_ctx, attempts=20)
    echo_roundtrip(warmup, b'warmup')
    warmup.close()
    print_ok("warm-up connection OK")

    # Phase 1: contention churn with mixed normal/abnormal exits
    start = time.time()
    results = {}
    threads = [threading.Thread(target=churn_worker, args=(n, results))
               for n in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    total = NUM_THREADS * ITERS_PER_THREAD
    successes = sum(ok for ok, _ in results.values())
    errors = [err for _, err in results.values() if err is not None]
    if errors or successes != total:
        raise Exception(
            "expected {0} successful iterations, got {1}; errors: {2}".format(
                total, successes, errors))
    print_ok("churned {0} contended connections in {1:.1f}s "
             "({2} abandoned handshakes)".format(
                 total, time.time() - start, len(abandoned)))

    # Phase 2: all connections (including abandoned handshakes) must drain
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open returned to 0")

    # Now open exactly MAX_CONCURRENT simultaneous connections and prove
    # they all work concurrently -- i.e. all semaphore slots survived.
    ctx = make_client_context()
    conns = []
    try:
        for n in range(MAX_CONCURRENT):
            conns.append(tls_connect(ctx))
        for n, tls_sock in enumerate(conns):
            echo_roundtrip(tls_sock, 'capacity-{0}'.format(n).encode())
        print_ok("all {0} slots usable concurrently".format(MAX_CONCURRENT))
    finally:
        for tls_sock in conns:
            try:
                tls_sock.close()
            except OSError:
                pass

    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open returned to 0 after capacity check")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    for sock in abandoned:
        try:
            sock.close()
        except OSError:
            pass
    if backend:
        backend.stop()
