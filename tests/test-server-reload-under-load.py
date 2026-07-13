#!/usr/bin/env python3

"""
Ensures that certificate reloads do not disturb established connections or
corrupt in-flight data, and that new connections keep working across reloads.

Starts an echo backend and ghostunnel in server mode, then runs ten
long-lived client connections that continuously pump small echo roundtrips
(sha256-accumulating both directions). While the pumps run, triggers five
certificate reloads spaced ~1s apart (swapping in a freshly generated
server certificate before the third one). After each reload completes
(observed via the /_status 'last_reload' field), a brand-new connection
must still be able to do an echo roundtrip. At the end, every pump must
have completed with zero errors, matching sent/received hashes, and a
minimum number of roundtrips; the conn.open metric must drop back to zero.
"""

from common import LOCALHOST, RootCert, BackendServer, TlsClient, print_ok, \
    recv_exact, reload_args, run_ghostunnel, status_info, terminate, \
    trigger_reload, wait_for_metric, wait_for_status, \
    LISTEN_PORT, STATUS_PORT, TARGET_PORT, TIMEOUT

import hashlib
import os
import threading

NUM_PUMPS = 10
NUM_RELOADS = 5
PAYLOAD_SIZE = 1024
MIN_ROUNDTRIPS = 20

stop_event = threading.Event()


class Pump:
    """Long-lived connection continuously doing small echo roundtrips."""

    def __init__(self, index):
        self.index = index
        self.rounds = 0
        self.error = None
        self.sent = hashlib.sha256()
        self.rcvd = hashlib.sha256()
        self.client = TlsClient('client', 'root', LISTEN_PORT)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        # connect on the caller's thread so connection errors surface early
        self.client.connect(10)
        self.thread.start()

    def _run(self):
        try:
            sock = self.client.get_socket()
            while not stop_event.is_set():
                payload = os.urandom(PAYLOAD_SIZE)
                sock.sendall(payload)
                self.sent.update(payload)
                data = recv_exact(sock, PAYLOAD_SIZE)
                self.rcvd.update(data)
                self.rounds += 1
        except Exception as e:
            self.error = e


def new_connection_roundtrip(label):
    """Open a fresh connection and verify one echo roundtrip works."""
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect(10)
    try:
        payload = os.urandom(PAYLOAD_SIZE)
        client.get_socket().sendall(payload)
        data = recv_exact(client.get_socket(), PAYLOAD_SIZE)
        if data != payload:
            raise Exception('echo mismatch on {0}'.format(label))
        print_ok('{0}: echo roundtrip works'.format(label))
    finally:
        client.cleanup()


ghostunnel = None
backend = None
root = None
try:
    # create certs (new_server is swapped in before the third reload)
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('new_server')
    root.create_signed_cert('client')

    backend = BackendServer().start()

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args())

    wait_for_status(lambda info: info.get('message') == 'listening')

    # start long-lived pumps
    pumps = [Pump(i) for i in range(NUM_PUMPS)]
    for pump in pumps:
        pump.start()
    print_ok('{0} pumps started'.format(NUM_PUMPS))

    # wait until every pump has demonstrably made progress
    deadline_event = threading.Event()
    for pump in pumps:
        for _ in range(100):
            if pump.rounds > 0 or pump.error is not None:
                break
            deadline_event.wait(0.1)
        if pump.error is not None:
            raise pump.error
        if pump.rounds == 0:
            raise Exception('pump {0} made no progress'.format(pump.index))

    # trigger reloads while the pumps are running
    for i in range(NUM_RELOADS):
        if i == 2:
            # swap in a freshly generated server certificate; the reload
            # below must pick it up without disturbing existing conns
            os.replace('new_server.p12', 'server.p12')
            print_ok('swapped server certificate on disk')

        pre = status_info()
        pre_reload = pre.get('last_reload') if pre else None
        trigger_reload(ghostunnel)
        wait_for_status(lambda info: info.get('last_reload') != pre_reload
                        and info.get('message') == 'listening')
        print_ok('reload {0} complete'.format(i + 1))

        # new connections must keep working after each reload
        new_connection_roundtrip('post-reload-{0} connection'.format(i + 1))

        # space the reloads out (~1s) while the pumps keep running;
        # this is pacing for load generation, not synchronization
        stop_event.wait(1.0)

    # stop the pumps and check results
    stop_event.set()
    for pump in pumps:
        pump.thread.join(TIMEOUT)
        if pump.thread.is_alive():
            raise Exception('pump {0} did not stop in time'.format(pump.index))

    for pump in pumps:
        if pump.error is not None:
            raise Exception('pump {0} failed after {1} roundtrips: {2}'.format(
                pump.index, pump.rounds, pump.error))
        if pump.rounds < MIN_ROUNDTRIPS:
            raise Exception('pump {0} only completed {1} roundtrips'.format(
                pump.index, pump.rounds))
        if pump.sent.hexdigest() != pump.rcvd.hexdigest():
            raise Exception('pump {0} data corruption: sent {1} != rcvd {2}'.format(
                pump.index, pump.sent.hexdigest(), pump.rcvd.hexdigest()))

    print_ok('all pumps OK, roundtrips: {0}'.format(
        [pump.rounds for pump in pumps]))

    if ghostunnel.poll() is not None:
        raise Exception('ghostunnel exited unexpectedly (rc={0})'.format(
            ghostunnel.returncode))

    # close pump connections; open connection count must drop back to zero
    for pump in pumps:
        pump.client.cleanup()
    wait_for_metric('ghostunnel.conn.open', lambda v: v == 0)
    print_ok('conn.open back to 0')

    print_ok('OK')
finally:
    stop_event.set()
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
