#!/usr/bin/env python3

"""
Ensures that concurrent TLS handshakes with an OPA policy do not serialize,
deadlock, or leak connections.

Part 1 (throughput): with the allow-all policy bundle loaded, 8 threads
each make 10 sequential connections with an echo roundtrip; all 80 must
succeed and the conn.open metric must return to zero.

Part 2 (slow policy concurrency): loads a deliberately slow Rego policy
(materializes a 4M-element numbers.range per evaluation, ~1-2s) and opens
5 connections concurrently. All must succeed, and the total wall time must
be much closer to a single policy delay than to 5x, proving evaluations
run concurrently. The repo's checked-in slow bundle (numbers.range of 50M,
~30-45s per eval) is far too slow for the test runtime budget, so this
test generates a scaled-down slow policy at runtime instead.
"""

from common import LOCALHOST, BackendServer, create_default_certs, \
    print_ok, recv_exact, run_ghostunnel, terminate, wait_for_metric, \
    wait_for_status, LISTEN_PORT, STATUS_PORT, TARGET_PORT

from tempfile import mkdtemp
import os
import shutil
import socket
import ssl
import threading
import time

THROUGHPUT_THREADS = 8
THROUGHPUT_CONNS = 10
SLOW_CONCURRENT_CONNS = 5

# Scaled-down version of tests/test-server-opa-slow-policy.tar.gz: the rule
# materializes a large numbers.range on every evaluation, delaying the
# handshake by roughly 1-2s, then allows certs with a "client" DNS SAN.
# (Written as a v0 rego policy: ghostunnel loads bare .rego files as v0.)
SLOW_REGO = """package policy

default allow = false

allow {
    count(numbers.range(1, 4000000)) == 4000000
    input.certificate.DNSNames[_] == "client"
}
"""


def echo_roundtrip(timeout):
    """Fresh TLS connection + echo roundtrip. Returns elapsed seconds."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client.crt', 'client.key')
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    sock = ctx.wrap_socket(raw, server_hostname=LOCALHOST)
    start = time.time()
    try:
        sock.connect((LOCALHOST, LISTEN_PORT))
        payload = os.urandom(1024)
        sock.sendall(payload)
        data = recv_exact(sock, 1024)
        if data != payload:
            raise Exception('echo mismatch')
        return time.time() - start
    finally:
        sock.close()


ghostunnel = None
backend = None
root = None
tmp_dir = None
try:
    root = create_default_certs()
    backend = BackendServer().start()
    dir_path = os.path.dirname(os.path.realpath(__file__))

    ############################################################
    # Part 1: throughput with the allow-all policy bundle
    ############################################################
    tmp_dir = mkdtemp()
    shutil.copyfile(dir_path + '/test-allow-all-policy.tar.gz',
                    tmp_dir + '/bundle.tar.gz')

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-policy=' + tmp_dir + '/bundle.tar.gz',
                                 '--allow-query=data.policy.allow',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])
    wait_for_status(lambda info: info.get('message') == 'listening')

    successes = []
    errors = []

    def throughput_worker(thread_id):
        for i in range(THROUGHPUT_CONNS):
            try:
                echo_roundtrip(timeout=30)
                successes.append((thread_id, i))
            except Exception as e:
                errors.append('thread {0} conn {1}: {2}'.format(thread_id, i, e))

    threads = [threading.Thread(target=throughput_worker, args=(t,), daemon=True)
               for t in range(THROUGHPUT_THREADS)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
        if t.is_alive():
            raise Exception('throughput worker did not finish in time')

    if errors:
        raise Exception('throughput errors ({0} of {1} succeeded): {2}'.format(
            len(successes), THROUGHPUT_THREADS * THROUGHPUT_CONNS, errors))
    print_ok('part 1: {0} concurrent connections all succeeded'.format(
        len(successes)))

    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok('part 1: conn.open back to 0')

    terminate(ghostunnel)
    if ghostunnel.returncode is None:
        raise Exception('ghostunnel (part 1) did not terminate')
    ghostunnel = None

    ############################################################
    # Part 2: concurrency with a slow policy
    ############################################################
    with open('slow-policy.rego', 'w') as f:
        f.write(SLOW_REGO)

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-policy=slow-policy.rego',
                                 '--allow-query=data.policy.allow',
                                 '--connect-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])
    wait_for_status(lambda info: info.get('message') == 'listening')

    # measure the single-connection policy delay (one warmup, then two
    # measurements; take the slowest so the concurrency bound below is
    # conservative rather than artificially tight)
    echo_roundtrip(timeout=60)  # warmup (first eval can be slower)
    single_delay = max(echo_roundtrip(timeout=60), echo_roundtrip(timeout=60))
    print_ok('part 2: single-connection delay {0:.2f}s'.format(single_delay))

    # The policy evaluation is CPU-bound, so wall-time can only demonstrate
    # concurrency when the machine has enough cores to actually run the
    # evaluations in parallel. On small or fast machines we still require
    # all concurrent connections to succeed, but skip the timing assertion.
    cpu_count = os.cpu_count() or 1
    enforce_timing = cpu_count >= 4 and single_delay >= 0.2
    if not enforce_timing:
        print_ok('part 2: skipping timing assertion '
                 '({0} cpus, {1:.3f}s single delay)'.format(
                     cpu_count, single_delay))

    # open connections concurrently; all must succeed
    conc_errors = []
    conc_times = []

    def slow_worker(i):
        try:
            conc_times.append(echo_roundtrip(timeout=60))
        except Exception as e:
            conc_errors.append('conn {0}: {1}'.format(i, e))

    threads = [threading.Thread(target=slow_worker, args=(i,), daemon=True)
               for i in range(SLOW_CONCURRENT_CONNS)]
    conc_start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
        if t.is_alive():
            raise Exception('slow-policy connection did not finish in time')
    total = time.time() - conc_start

    if conc_errors:
        raise Exception('slow-policy concurrent errors: {0}'.format(conc_errors))

    # Serialized evaluation would take ~N * single_delay. Require total to
    # beat that by at least one full delay (plus a constant for handshake
    # and scheduling overhead). This deliberately leaves headroom for CPU
    # contention from parallel tests: on an idle 4-core machine 5
    # concurrent evals finish in ~2.7x a single delay, versus 5x when
    # serialized.
    bound = (SLOW_CONCURRENT_CONNS - 1) * single_delay + 1.0
    print_ok('part 2: {0} concurrent conns in {1:.2f}s '
             '({2:.2f}x single delay, bound {3:.2f}s, serialized would be '
             '~{4:.2f}s)'.format(SLOW_CONCURRENT_CONNS, total,
                                 total / single_delay, bound,
                                 SLOW_CONCURRENT_CONNS * single_delay))
    if enforce_timing and total >= bound:
        raise Exception('concurrent evaluations appear serialized: '
                        '{0:.2f}s >= bound {1:.2f}s '
                        '(single delay {2:.2f}s)'.format(
                            total, bound, single_delay))

    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok('part 2: conn.open back to 0')

    print_ok('OK')
finally:
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    try:
        os.remove('slow-policy.rego')
    except OSError:
        pass  # only exists if part 2 ran; nothing to clean otherwise
