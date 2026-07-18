#!/usr/bin/env python3

"""
Floods ghostunnel with slowloris-style clients (silent sockets and garbage
senders that never complete a TLS handshake) and verifies that legitimate
clients are not starved, that the stuck handshakes are reaped by
--connect-timeout, and that connection/goroutine accounting returns to
baseline afterwards.
"""

from common import LISTEN_PORT, LOCALHOST, BackendServer, TlsClient, \
    create_default_certs, goroutine_count, print_ok, recv_exact, \
    start_ghostunnel_server, terminate, wait_for_metric
import socket
import time

SILENT_CONNS = 40
GARBAGE_CONNS = 20


def echo_roundtrip(payload):
    """Connect a legitimate TLS client and verify an echo roundtrip."""
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    try:
        sock = client.get_socket()
        sock.sendall(payload)
        data = recv_exact(sock, len(payload))
        if data != payload:
            raise Exception(
                "echo mismatch: sent {0!r}, got {1!r}".format(payload, data))
    finally:
        client.cleanup()


def wait_for_goroutines(baseline, tolerance=10, timeout=30):
    """Poll until the goroutine count drops to baseline + tolerance."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            last = goroutine_count()
            if last <= baseline + tolerance:
                return last
        except Exception as e:
            print('unable to fetch goroutine count:', e)
        time.sleep(0.5)
    raise Exception(
        "goroutine count did not return to baseline {0} (+{1}) after {2}s, "
        "last value: {3}".format(baseline, tolerance, timeout, last))


ghostunnel = None
backend = None
root = None
flood = []
try:
    # create certs and start echo backend
    root = create_default_certs()
    backend = BackendServer().start()

    # start ghostunnel with a short handshake timeout
    ghostunnel = start_ghostunnel_server(extra_args=[
        '--connect-timeout=1s',
        '--enable-pprof',
    ])

    # warm-up: wait for startup by doing a legit echo roundtrip
    echo_roundtrip(b'warmup')
    print_ok("warm-up echo roundtrip works")

    # wait for the warm-up connection to be fully closed, then record the
    # goroutine baseline
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    baseline = goroutine_count()
    print_ok("goroutine baseline: {0}".format(baseline))

    # flood phase: open silent sockets that never send anything, plus
    # sockets that send garbage (not a valid ClientHello) and then stall.
    # all sockets are kept open, we do not close them yet.
    for _ in range(SILENT_CONNS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((LOCALHOST, LISTEN_PORT))
        flood.append(s)
    for _ in range(GARBAGE_CONNS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((LOCALHOST, LISTEN_PORT))
        s.sendall(b'GET / HTTP/1.0\r\n')
        flood.append(s)
    print_ok("opened {0} flood connections".format(len(flood)))

    # while the flood sockets are held open, legitimate clients must still
    # be able to connect and complete echo roundtrips
    for i in range(3):
        echo_roundtrip('legit-{0}'.format(i).encode('utf-8'))
        print_ok("legit roundtrip {0} works during flood".format(i + 1))
        time.sleep(0.7)

    # the silent sockets must all hit the handshake timeout. (the garbage
    # senders fail the handshake immediately with a record error, which
    # counts as accept.error, not accept.timeout.)
    timeouts = wait_for_metric(
        'ghostunnel.accept.timeout', lambda v: v >= SILENT_CONNS, timeout=30)
    print_ok("observed {0} handshake timeouts".format(timeouts))

    # close all flood sockets, then verify accounting returns to baseline
    for s in flood:
        try:
            s.close()
        except OSError:
            pass  # flood sockets may already be reaped by ghostunnel
    flood = []

    open_conns = wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open back to {0}".format(open_conns))

    goroutines = wait_for_goroutines(baseline)
    print_ok("goroutines back to {0} (baseline {1})".format(
        goroutines, baseline))

    # a final legitimate connection must work
    echo_roundtrip(b'final')
    print_ok("final echo roundtrip works")

    print_ok("OK")
finally:
    for s in flood:
        try:
            s.close()
        except OSError:
            pass  # best-effort teardown, sockets may already be dead
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
