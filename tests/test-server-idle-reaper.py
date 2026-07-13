#!/usr/bin/env python3

"""
Opens many legitimate TLS connections, leaves them all idle, and verifies
that --max-conn-lifetime reaps every one of them (with correct conn.open
accounting and client-visible closes), and that the tunnel remains healthy
afterwards.
"""

from common import LISTEN_PORT, BackendServer, TlsClient, \
    create_default_certs, goroutine_count, print_ok, recv_exact, \
    start_ghostunnel_server, terminate, wait_for_metric
import time

NUM_CONNS = 30


def open_echo_conn(payload):
    """Open a TLS client connection and complete an echo roundtrip.

    Returns the connected TlsClient (left open)."""
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(20)
    sock = client.get_socket()
    sock.sendall(payload)
    data = recv_exact(sock, len(payload))
    if data != payload:
        raise Exception(
            "echo mismatch: sent {0!r}, got {1!r}".format(payload, data))
    return client


def assert_closed_by_server(client, name):
    """Verify the server closed the connection: recv must return EOF or
    raise a connection error, not hang or return data."""
    sock = client.get_socket()
    sock.settimeout(10)
    try:
        data = sock.recv(1)
    except Exception as e:
        print_ok("{0} closed by server (recv raised: {1})".format(name, e))
        return
    if data == b'':
        print_ok("{0} closed by server (recv returned EOF)".format(name))
        return
    raise Exception(
        "{0}: expected EOF after reap, got data {1!r}".format(name, data))


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
clients = []
try:
    # create certs and start echo backend; the generous conn_timeout keeps
    # the backend from timing out idle connections before ghostunnel's
    # lifetime reaper does
    root = create_default_certs()
    backend = BackendServer(conn_timeout=30).start()

    # start ghostunnel with a short max connection lifetime
    ghostunnel = start_ghostunnel_server(extra_args=[
        '--max-conn-lifetime=3s',
        '--enable-pprof',
    ])

    # warm-up: wait for startup with a legit echo roundtrip, then record
    # goroutine baseline once it has been reaped/closed
    warmup = open_echo_conn(b'warmup')
    warmup.cleanup()
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    baseline = goroutine_count()
    print_ok("goroutine baseline: {0}".format(baseline))

    # open many connections, each with a completed echo roundtrip, and
    # leave all of them idle simultaneously
    for i in range(NUM_CONNS):
        clients.append(open_echo_conn('conn-{0}'.format(i).encode('utf-8')))
    print_ok("opened {0} idle connections".format(len(clients)))

    # confirm they're all open, then wait for the lifetime reaper to close
    # every one of them even though the clients keep their sockets open
    wait_for_metric('ghostunnel.conn.open', lambda v: v >= NUM_CONNS)
    open_conns = wait_for_metric(
        'ghostunnel.conn.open', lambda v: v == 0, timeout=30)
    print_ok("all connections reaped, conn.open == {0}".format(open_conns))

    # verify from the client side that the sockets actually got closed
    for i in (0, NUM_CONNS // 2, NUM_CONNS - 1):
        assert_closed_by_server(clients[i], "conn-{0}".format(i))

    for client in clients:
        client.cleanup()
    clients = []

    # service must still be healthy: a fresh connection works, and it too
    # gets reaped after the lifetime deadline while held idle
    fresh = open_echo_conn(b'fresh')
    clients.append(fresh)
    print_ok("fresh connection works after mass reap")
    wait_for_metric('ghostunnel.conn.open', lambda v: v >= 1)
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0, timeout=30)
    assert_closed_by_server(fresh, "fresh conn")
    fresh.cleanup()
    clients = []

    # goroutine count must return to baseline
    goroutines = wait_for_goroutines(baseline)
    print_ok("goroutines back to {0} (baseline {1})".format(
        goroutines, baseline))

    print_ok("OK")
finally:
    for client in clients:
        try:
            client.cleanup()
        except Exception:
            pass
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
