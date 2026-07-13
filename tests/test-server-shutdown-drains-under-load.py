#!/usr/bin/env python3

"""
Ensures that SIGTERM during active transfers drains gracefully: in-flight
connections are allowed to complete, no new connections are accepted, and
the process exits with code 0 once the connections have drained.

Starts an echo backend and ghostunnel with --shutdown-timeout=30s, opens
five connections each pumping a fixed 8 MiB total through the tunnel in
64 KiB echo roundtrips. Once every pump has transferred its first 1 MiB,
the pumps pause at a barrier while the test sends SIGTERM. The test then
verifies that new connections are refused (polled: the listener may take
a moment to close) while ghostunnel keeps running, releases the pumps to
finish their remaining 7 MiB each, verifies every transfer completed with
intact hashes (finishing with a client half-close and a clean EOF), and
finally checks that ghostunnel exits 0 well before the shutdown timeout.
"""

from common import IS_WINDOWS, LOCALHOST, BackendServer, TlsClient, \
    create_default_certs, print_ok, recv_exact, start_ghostunnel_server, \
    terminate, wait_for_status, LISTEN_PORT, TIMEOUT

import hashlib
import os
import signal
import socket
import threading
import time

NUM_PUMPS = 5
CHUNK_SIZE = 64 * 1024
TOTAL_BYTES = 8 * 1024 * 1024
TOTAL_ROUNDS = TOTAL_BYTES // CHUNK_SIZE          # 128
PRE_SIGNAL_ROUNDS = 1024 * 1024 // CHUNK_SIZE     # 16 rounds = 1 MiB

# pumps set their 'reached' event after PRE_SIGNAL_ROUNDS, then wait on
# this barrier until the test has sent SIGTERM
proceed_event = threading.Event()


class Pump:
    """Transfers a fixed total through the tunnel in echo roundtrips."""

    def __init__(self, index):
        self.index = index
        self.rounds = 0
        self.error = None
        self.completed = False
        self.reached = threading.Event()
        self.sent = hashlib.sha256()
        self.rcvd = hashlib.sha256()
        self.client = TlsClient('client', 'root', LISTEN_PORT)
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.client.connect(10)
        self.thread.start()

    def _run(self):
        try:
            sock = self.client.get_socket()
            for r in range(TOTAL_ROUNDS):
                if r == PRE_SIGNAL_ROUNDS:
                    # mid-stream: signal the main thread and wait for it to
                    # deliver SIGTERM before transferring the remainder
                    self.reached.set()
                    if not proceed_event.wait(3 * TIMEOUT):
                        raise Exception('timed out waiting for proceed event')
                payload = os.urandom(CHUNK_SIZE)
                sock.sendall(payload)
                self.sent.update(payload)
                data = recv_exact(sock, CHUNK_SIZE)
                self.rcvd.update(data)
                self.rounds += 1
            # All echoed data has already been read back by the synchronous
            # roundtrips; no decrypted data may be left buffered.
            if sock.pending() != 0:
                raise Exception('unexpected {0} pending bytes'.format(sock.pending()))
            # Half-close and drain to EOF. Note: SSLSocket.shutdown() drops
            # the SSL layer, so subsequent recv() returns raw TLS records
            # (e.g. the close_notify alert) — we only verify that the tunnel
            # propagates the FIN and the connection reaches EOF, without
            # interpreting the remaining raw bytes.
            sock.shutdown(socket.SHUT_WR)
            while sock.recv(4096):
                pass
            if self.sent.hexdigest() != self.rcvd.hexdigest():
                raise Exception('data corruption: sent {0} != rcvd {1}'.format(
                    self.sent.hexdigest(), self.rcvd.hexdigest()))
            self.completed = True
        except Exception as e:
            self.error = e
            self.reached.set()  # never leave the main thread waiting


ghostunnel = None
backend = None
root = None
try:
    root = create_default_certs()
    backend = BackendServer().start()

    # Override the harness's default 1s shutdown timeout: we want ghostunnel
    # to wait for our in-flight transfers to complete after SIGTERM.
    ghostunnel = start_ghostunnel_server(extra_args=['--shutdown-timeout=30s'])
    wait_for_status(lambda info: info.get('message') == 'listening')

    pumps = [Pump(i) for i in range(NUM_PUMPS)]
    for pump in pumps:
        pump.start()

    # wait until every pump is mid-stream (>= 1 MiB transferred)
    for pump in pumps:
        if not pump.reached.wait(3 * TIMEOUT):
            raise Exception('pump {0} did not reach mid-stream'.format(pump.index))
        if pump.error is not None:
            raise pump.error
    print_ok('all pumps mid-stream (1 MiB each), sending SIGTERM')

    # send SIGTERM (graceful shutdown) while transfers are in flight
    if IS_WINDOWS:
        ghostunnel.send_signal(signal.CTRL_BREAK_EVENT)
    else:
        ghostunnel.terminate()

    # new connections must be refused once the listener closes; allow a
    # brief race window right after signaling by polling until refused
    refused = False
    deadline = time.time() + TIMEOUT
    while time.time() < deadline:
        try:
            probe = socket.create_connection((LOCALHOST, LISTEN_PORT), timeout=2)
            probe.close()
            time.sleep(0.1)
        except ConnectionRefusedError:
            refused = True
            break
        except OSError:
            time.sleep(0.1)
    if not refused:
        raise Exception('new connections still accepted after SIGTERM')
    print_ok('new connections refused after SIGTERM')

    # ghostunnel must still be draining (our 5 connections are open)
    if ghostunnel.poll() is not None:
        raise Exception('ghostunnel exited before connections drained '
                        '(rc={0})'.format(ghostunnel.returncode))
    print_ok('ghostunnel still draining while connections are open')

    # release the pumps to complete their transfers post-signal
    proceed_event.set()
    for pump in pumps:
        pump.thread.join(3 * TIMEOUT)
        if pump.thread.is_alive():
            raise Exception('pump {0} did not finish in time'.format(pump.index))

    for pump in pumps:
        if pump.error is not None:
            raise Exception('pump {0} failed after {1} rounds: {2}'.format(
                pump.index, pump.rounds, pump.error))
        if not pump.completed:
            raise Exception('pump {0} did not complete'.format(pump.index))
    print_ok('all pumps completed their 8 MiB transfers after SIGTERM')

    # close client sockets so ghostunnel can finish draining
    for pump in pumps:
        pump.client.cleanup()

    # ghostunnel must now exit cleanly (exit code 0), well before the 30s
    # shutdown timeout would force a non-zero exit
    ret = ghostunnel.wait(timeout=2 * TIMEOUT)
    if ret != 0:
        raise Exception('ghostunnel exited with code {0}, '
                        'expected graceful exit 0'.format(ret))
    print_ok('ghostunnel exited 0 after drain')

    print_ok('OK')
finally:
    proceed_event.set()
    terminate(ghostunnel)
    if backend:
        backend.stop()
    if root:
        root.cleanup()
