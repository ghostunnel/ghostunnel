#!/usr/bin/env python3

"""
Opens and closes many short-lived TLS connections through a ghostunnel
server instance and verifies that no resources are leaked: open-connection
metrics return to zero, accept counters add up, goroutine counts return to
baseline, and (on Linux) file descriptor counts return to baseline.
"""

from common import BackendServer, LOCALHOST, LISTEN_PORT, TARGET_PORT, \
    TcpClient, STATUS_PORT, create_default_certs, fd_count, get_metrics, \
    goroutine_count, print_ok, recv_exact, start_ghostunnel_server, \
    terminate, wait_for_metric, TIMEOUT, _poll_sleep
import socket
import ssl
import threading
import time

NUM_THREADS = 6
CONNS_PER_THREAD = 100
TOTAL_CONNS = NUM_THREADS * CONNS_PER_THREAD
CONNECT_ATTEMPTS = 3

# Counts individual failed connect attempts that were retried. Used to
# relax the exact backend-accept count: a failed attempt could in rare
# cases still have registered as an accepted connection server-side.
retried_attempts = 0
retried_lock = threading.Lock()


def make_client_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client.crt', 'client.key')
    return ctx


def tls_connect(ctx, attempts=CONNECT_ATTEMPTS):
    """Connect a TLS client through the tunnel, with a few retries to
    absorb transient hiccups on busy parallel CI machines."""
    global retried_attempts
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
            with retried_lock:
                retried_attempts += 1
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
        for i in range(CONNS_PER_THREAD):
            tls_sock = tls_connect(ctx)
            try:
                payload = 'churn-{0}-{1}'.format(thread_id, i).encode()
                echo_roundtrip(tls_sock, payload)
            finally:
                tls_sock.close()
            ok += 1
    except Exception as e:
        results[thread_id] = (ok, e)
        return
    results[thread_id] = (ok, None)


def wait_for_value(fetch, predicate, what, timeout=30):
    """Poll fetch() until predicate(value) is truthy; raise on timeout."""
    deadline = time.time() + timeout
    iteration = 0
    last = None
    while time.time() < deadline:
        try:
            last = fetch()
            if predicate(last):
                return last
        except Exception as e:
            last = e
        _poll_sleep(iteration)
        iteration += 1
    raise Exception("{0} did not converge after {1}s (last: {2})".format(
        what, timeout, last))


ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()

    backend = BackendServer().start()
    ghostunnel = start_ghostunnel_server(extra_args=['--enable-pprof'])

    # wait for startup and do a warm-up connection
    TcpClient(STATUS_PORT).connect(20)
    warmup_ctx = make_client_context()
    warmup = tls_connect(warmup_ctx, attempts=20)
    echo_roundtrip(warmup, b'warmup')
    warmup.close()
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("warm-up connection OK")

    # record baselines (post warm-up, all connections drained)
    baseline_goroutines = wait_for_value(
        goroutine_count, lambda v: v > 0, "baseline goroutine count", timeout=10)
    baseline_fds = fd_count(ghostunnel.pid)
    print_ok("baselines: goroutines={0}, fds={1}".format(
        baseline_goroutines, baseline_fds))

    # churn: NUM_THREADS threads, each doing CONNS_PER_THREAD sequential
    # short-lived echo connections
    start = time.time()
    results = {}
    threads = [threading.Thread(target=churn_worker, args=(n, results))
               for n in range(NUM_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = sum(ok for ok, _ in results.values())
    errors = [err for _, err in results.values() if err is not None]
    if errors or successes != TOTAL_CONNS:
        raise Exception(
            "expected {0} successful connections, got {1}; errors: {2}".format(
                TOTAL_CONNS, successes, errors))
    print_ok("churned {0} connections in {1:.1f}s".format(
        TOTAL_CONNS, time.time() - start))

    # all connections must drain
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open returned to 0")

    # accept counter must have seen at least all our connections (+ warmup)
    metrics = get_metrics()
    accept_total = metrics['ghostunnel.accept.total']
    if accept_total < TOTAL_CONNS + 1:
        raise Exception("accept.total is {0}, expected >= {1}".format(
            accept_total, TOTAL_CONNS + 1))
    print_ok("accept.total={0} (>= {1})".format(accept_total, TOTAL_CONNS + 1))

    # backend must have seen exactly one connection per tunnel connection
    # (retried connect attempts get a small allowance, since a failed
    # attempt could still have reached the backend in rare cases)
    expected_accepted = TOTAL_CONNS + 1  # + warmup
    if not (expected_accepted <= backend.accepted
            <= expected_accepted + retried_attempts):
        raise Exception(
            "backend accepted {0} connections, expected {1} (+{2} retries)".format(
                backend.accepted, expected_accepted, retried_attempts))
    print_ok("backend accepted {0} connections ({1} retried attempts)".format(
        backend.accepted, retried_attempts))

    # goroutine count must return to (near) baseline
    final_goroutines = wait_for_value(
        goroutine_count, lambda v: v <= baseline_goroutines + 10,
        "goroutine count (baseline {0})".format(baseline_goroutines))
    print_ok("goroutines: baseline={0}, final={1}".format(
        baseline_goroutines, final_goroutines))

    # fd count must return to (near) baseline, where measurable
    if baseline_fds is not None:
        final_fds = wait_for_value(
            lambda: fd_count(ghostunnel.pid),
            lambda v: v is not None and v <= baseline_fds + 10,
            "fd count (baseline {0})".format(baseline_fds))
        print_ok("fds: baseline={0}, final={1}".format(
            baseline_fds, final_fds))
    else:
        print_ok("fd count not measurable on this platform, skipping check")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
