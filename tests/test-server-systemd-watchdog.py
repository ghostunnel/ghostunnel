#!/usr/bin/env python3

"""
Spins up a server with NOTIFY_SOCKET / WATCHDOG_USEC set (simulating systemd
service supervision) and asserts that ghostunnel:

  - sends READY=1 once it is listening,
  - sends WATCHDOG=1 keepalives at WATCHDOG_USEC/2,
  - sends RELOADING=1 followed by READY=1 in response to SIGUSR1,
  - sends STOPPING=1 in response to SIGTERM.

This exercises handleServiceWatchdog (status_linux.go) and notifyService*
end-to-end. A regression in the keepalive loop would cause systemd to kill
production instances, so the test asserts at least two WATCHDOG=1 datagrams
arrive within roughly one watchdog interval.
"""

import os
import signal
import socket
import time
from tempfile import mkdtemp

from common import (LISTEN_PORT, LOCALHOST, STATUS_PORT, TARGET_PORT, RootCert,
                    SocketPair, TcpServer, TlsClient, print_ok,
                    require_platform, run_ghostunnel, terminate)

# handleServiceWatchdog / notifyService* are only wired up on Linux
# (status_linux.go). On darwin/BSD the sd_notify path is a no-op stub
# (status_other.go), so there is nothing meaningful to exercise.
require_platform('Linux')


def recv_datagrams_until(sock, deadline, predicate):
    """Drain datagrams from sock until predicate(messages) is truthy or
    deadline (a monotonic time) elapses. Returns the list of messages
    collected so far (regardless of whether predicate was satisfied)."""
    messages = []
    while time.monotonic() < deadline:
        remaining = deadline - time.monotonic()
        sock.settimeout(max(0.05, remaining))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        # sd_notify allows multiple newline-separated messages per datagram
        # (e.g. "RELOADING=1\nMONOTONIC_USEC=123"). Split so we can match
        # individual fields.
        text = data.decode('utf-8', errors='replace')
        for line in text.split('\n'):
            line = line.strip()
            if line:
                messages.append(line)
        if predicate(messages):
            return messages
    return messages


def wait_for_message(sock, target, timeout):
    """Block until `target` appears in a received datagram, or raise."""
    deadline = time.monotonic() + timeout
    messages = recv_datagrams_until(
        sock, deadline, lambda msgs: target in msgs)
    if target not in messages:
        raise Exception(
            "did not receive {0!r} within {1}s; got: {2!r}".format(
                target, timeout, messages))
    return messages


ghostunnel = None
notify_dir = mkdtemp(prefix='ghostunnel-sdnotify-')
notify_path = os.path.join(notify_dir, 'notify.sock')
notify_sock = None
try:
    notify_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify_sock.bind(notify_path)

    # Watchdog interval: 1s. ghostunnel pings every WATCHDOG_USEC/2 = 500ms.
    # We deliberately leave WATCHDOG_PID unset: SdWatchdogEnabled only
    # checks PID equality when WATCHDOG_PID is set, so omitting it makes
    # the watchdog active in the child without us having to predict its PID.
    os.environ['NOTIFY_SOCKET'] = notify_path
    os.environ['WATCHDOG_USEC'] = '1000000'
    os.environ.pop('WATCHDOG_PID', None)

    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    try:
        ghostunnel = run_ghostunnel([
            'server',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
            '--keystore=server.p12',
            '--cacert=root.crt',
            '--allow-ou=client',
            '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])
    finally:
        # Don't leak NOTIFY_SOCKET / WATCHDOG_USEC into other test invocations
        # that might share the python process (defensive: tests are normally
        # per-process, but common.py manipulates os.environ as a baseline).
        del os.environ['NOTIFY_SOCKET']
        del os.environ['WATCHDOG_USEC']

    # 1) Expect READY=1 once the proxy is listening.
    wait_for_message(notify_sock, 'READY=1', timeout=10)
    print_ok("got READY=1")

    # Sanity check the proxy actually works end-to-end while watchdog pings
    # are running in the background.
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.cleanup()

    # 2) Expect at least 2 WATCHDOG=1 datagrams within ~2.5s. The keepalive
    # ticker fires every WATCHDOG_USEC/2 = 500ms, so even with some
    # scheduling jitter we should comfortably see two.
    deadline = time.monotonic() + 2.5
    msgs = recv_datagrams_until(
        notify_sock, deadline,
        lambda m: m.count('WATCHDOG=1') >= 2)
    watchdog_count = msgs.count('WATCHDOG=1')
    if watchdog_count < 2:
        raise Exception(
            "expected >= 2 WATCHDOG=1 keepalives within 2.5s; got {0}: {1!r}".format(
                watchdog_count, msgs))
    print_ok("got {0} WATCHDOG=1 keepalives".format(watchdog_count))

    # 3) SIGUSR1 -> RELOADING=1 then READY=1.
    ghostunnel.send_signal(signal.SIGUSR1)
    wait_for_message(notify_sock, 'RELOADING=1', timeout=5)
    print_ok("got RELOADING=1 after SIGUSR1")
    wait_for_message(notify_sock, 'READY=1', timeout=5)
    print_ok("got READY=1 after reload")

    # 4) SIGTERM -> STOPPING=1.
    ghostunnel.send_signal(signal.SIGTERM)
    wait_for_message(notify_sock, 'STOPPING=1', timeout=5)
    print_ok("got STOPPING=1 after SIGTERM")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if notify_sock is not None:
        try:
            notify_sock.close()
        except OSError:
            # best-effort teardown
            pass
    try:
        os.remove(notify_path)
    except OSError:
        # best-effort teardown: socket file may already be gone
        pass
    try:
        os.rmdir(notify_dir)
    except OSError:
        # best-effort teardown: directory may already be gone
        pass
