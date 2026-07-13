#!/usr/bin/env python3

"""
Runs ghostunnel under a low file descriptor limit (via prlimit), exhausts
its fds with a flood of held-open TCP connections so the accept loop hits
EMFILE, and verifies that the accept-error backoff path keeps the process
alive and that service recovers once the pressure goes away.
"""

from common import LISTEN_PORT, LOCALHOST, BackendServer, TlsClient, \
    create_default_certs, print_ok, recv_exact, require_platform, \
    start_ghostunnel_server, terminate, wait_for_metric
import shutil
import socket
import sys
import time

require_platform('Linux')
if not shutil.which('prlimit'):
    print("prlimit not available, skipping", file=sys.stderr)
    sys.exit(2)

# Low enough that ~100 held-open connections exhaust it, high enough that
# ghostunnel (Go runtime + listener + status endpoint + coverage) starts
# cleanly.
NOFILE_LIMIT = 64
FLOOD_CONNS = 100
LOG_FILE = 'ghostunnel-accept-error.log'


def echo_roundtrip(payload, attempts=20):
    """Connect a legitimate TLS client and verify an echo roundtrip."""
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(attempts)
    try:
        sock = client.get_socket()
        sock.sendall(payload)
        data = recv_exact(sock, len(payload))
        if data != payload:
            raise Exception(
                "echo mismatch: sent {0!r}, got {1!r}".format(payload, data))
    finally:
        client.cleanup()


ghostunnel = None
backend = None
root = None
log = None
flood = []
try:
    # create certs and start echo backend
    root = create_default_certs()
    backend = BackendServer().start()

    # start ghostunnel under a low fd limit, capturing output so we can
    # verify EMFILE ("too many open files") was actually hit
    log = open(LOG_FILE, 'wb')
    ghostunnel = start_ghostunnel_server(
        extra_args=['--connect-timeout=1s'],
        stdout=log, stderr=log,
        prefix=['prlimit', '--nofile={0}:{0}'.format(NOFILE_LIMIT)])

    # sanity-check startup under the fd limit
    echo_roundtrip(b'sanity')
    print_ok("sanity echo roundtrip works under fd limit")

    # exhaustion phase: hold open far more plain TCP connections than the
    # fd limit allows, without completing any handshake. ghostunnel accepts
    # until EMFILE, then the accept-backoff loop kicks in. (accepted-but-
    # unhandshaken conns are reaped by --connect-timeout=1s; holding well
    # over the limit keeps replenishing the pressure from the backlog.)
    for _ in range(FLOOD_CONNS):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.connect((LOCALHOST, LISTEN_PORT))
        except OSError as e:
            # backlog full / kernel refused: expected under pressure, but
            # keep the socket around so any half-open conn stays held
            print('flood connect failed (expected under pressure):', e)
        flood.append(s)
    print_ok("holding {0} flood connections".format(len(flood)))

    # accept errors must show up (EMFILE in the accept loop; handshake
    # failures also count, so additionally verify the accept-loop EMFILE
    # via the log below). the status endpoint may transiently fail to
    # accept under the fd limit; wait_for_metric polls through that.
    errors = wait_for_metric(
        'ghostunnel.accept.error', lambda v: v > 0, timeout=30)
    print_ok("observed {0} accept errors".format(errors))

    # deterministically prove the accept loop itself hit fd exhaustion
    deadline = time.time() + 30
    emfile_seen = False
    while time.time() < deadline:
        log.flush()
        with open(LOG_FILE, 'rb') as f:
            if b'too many open files' in f.read():
                emfile_seen = True
                break
        time.sleep(0.5)
    if not emfile_seen:
        raise Exception("never saw 'too many open files' in ghostunnel log")
    print_ok("accept loop hit EMFILE (too many open files)")

    # the process must have survived the fd exhaustion
    if ghostunnel.poll() is not None:
        raise Exception("ghostunnel died during fd exhaustion")
    print_ok("ghostunnel still alive under fd exhaustion")

    # recovery phase: release all the pressure
    for s in flood:
        try:
            s.close()
        except OSError:
            pass
    flood = []
    print_ok("closed all flood connections")

    # poll until a legitimate roundtrip succeeds (accept backoff maxes at
    # 1s, so recovery should be quick)
    deadline = time.time() + 20
    last_error = None
    recovered = False
    while time.time() < deadline:
        try:
            echo_roundtrip(b'recovery', attempts=1)
            recovered = True
            break
        except Exception as e:
            last_error = e
            time.sleep(0.5)
    if not recovered:
        raise Exception(
            "no successful roundtrip after releasing fd pressure") from last_error
    print_ok("first roundtrip after recovery works")

    # prove stable recovery with several more roundtrips
    for i in range(5):
        echo_roundtrip('stable-{0}'.format(i).encode('utf-8'))
    print_ok("5 more roundtrips work after recovery")

    # process alive, all connections drained
    if ghostunnel.poll() is not None:
        raise Exception("ghostunnel died after recovery")
    open_conns = wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok("conn.open back to {0}".format(open_conns))

    print_ok("OK")
finally:
    for s in flood:
        try:
            s.close()
        except OSError:
            pass
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if log:
        log.close()
        # replay captured ghostunnel output for debugging
        try:
            with open(LOG_FILE, 'rb') as f:
                sys.stderr.buffer.write(f.read())
        except OSError:
            pass
    if root:
        root.cleanup()
