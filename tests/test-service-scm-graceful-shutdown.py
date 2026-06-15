#!/usr/bin/env python3

"""
Tests graceful shutdown via the Windows SCM Stop path (not /_shutdown, which
test-service-graceful-shutdown.py already covers).

Why this exists: when the SCM stops a service, Execute is responsible for
sending periodic StopPending CheckPoint/WaitHint updates while the proxy
drains. Without them, the SCM may conclude the service is hung after
ServicesPipeTimeout (~30s default) and forcibly terminate the process,
truncating the drain and defeating the documented graceful-stop behavior.

Test design:
  1. Install a service with a long --shutdown-timeout so the drain has time
     to outlast a couple of progress ticks.
  2. Open an in-flight TLS connection through the proxy.
  3. Trigger 'ghostunnel service stop' on a background thread (the call
     blocks until SCM observes Stopped).
  4. Verify the connection's tail bytes still flow, then close it.
  5. Verify SCM reports Stopped, the service process exited cleanly, and
     the stop command returned success.

Requires Windows and Administrator privileges.
"""

import os
import subprocess
import sys
import threading
import time

from common import (LOCALHOST, LISTEN_PORT, TARGET_PORT,
                    SocketPair, TcpServer, TlsClient,
                    create_default_certs, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-scm-drain'

# Long enough that the StopPending wait outlasts at least one
# progressTickInterval (5s) and matches the kind of real drain SCM would
# otherwise time out on. Short enough to keep the test from dragging.
SHUTDOWN_TIMEOUT = '20s'
CLOSE_TIMEOUT = '20s'

root = None


def run_service_cmd(args, timeout=60):
    proc = run_ghostunnel(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=timeout)
    return proc.returncode, stdout.decode(), stderr.decode()


def uninstall_quietly():
    try:
        proc = run_ghostunnel(
            ['service', 'uninstall', '--service-name', SERVICE_NAME],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(timeout=30)
    except Exception:
        pass


def service_pid():
    """Return the SCM-reported PID for SERVICE_NAME, or 0 if stopped/missing."""
    ps_cmd = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "(Get-CimInstance Win32_Service -Filter \"Name='{0}'\").ProcessId"
    ).format(SERVICE_NAME)
    ps = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=15)
    out = (ps.stdout or '').strip()
    try:
        return int(out) if out else 0
    except ValueError:
        return 0


try:
    root = create_default_certs()
    keystore = os.path.abspath('server.p12')
    cacert = os.path.abspath('root.crt')

    uninstall_quietly()

    rc, stdout, stderr = run_service_cmd([
        'service', 'install', '--service-name', SERVICE_NAME,
        '--', 'server',
        '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--keystore={0}'.format(keystore),
        '--cacert={0}'.format(cacert),
        '--allow-ou=client',
        '--shutdown-timeout={0}'.format(SHUTDOWN_TIMEOUT),
        '--close-timeout={0}'.format(CLOSE_TIMEOUT),
    ])
    if rc != 0:
        print("install failed:\nstdout: {0}\nstderr: {1}".format(
            stdout, stderr), file=sys.stderr)
        raise Exception("service install failed (rc={0})".format(rc))
    print_ok("install: OK")

    pid_before = service_pid()
    if pid_before == 0:
        raise Exception("SCM reports the service has no PID after install")
    print_ok("service running as PID {0}".format(pid_before))

    # Establish an in-flight connection before SCM Stop.
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "send before SCM Stop")

    # Trigger 'ghostunnel service stop' on a background thread. It blocks
    # until SCM sees Stopped (waitForServiceRunningStopped polls), which
    # is what makes the periodic StopPending CheckPoint updates necessary.
    stop_result = {}

    def do_stop():
        try:
            stop_result['rc'], stop_result['out'], stop_result['err'] = run_service_cmd(
                ['service', 'stop', '--service-name', SERVICE_NAME],
                timeout=90)
        except Exception as exc:
            stop_result['exc'] = repr(exc)

    stop_thread = threading.Thread(target=do_stop)
    stop_thread.start()

    # Give the SCM a moment to enter StopPending before draining the
    # in-flight connection. Slow enough that at least one progress tick
    # fires before drain completes.
    time.sleep(7)

    # The in-flight connection must still flow after StopPending. If SCM
    # had killed the process, validate_can_send_from_server would fail
    # with a connection error.
    pair.validate_can_send_from_server("world", "send after SCM Stop, mid-drain")
    pair.validate_closing_client_closes_server("drain completes")

    stop_thread.join(timeout=90)
    if stop_thread.is_alive():
        raise Exception("'service stop' did not return within 90s")

    if 'exc' in stop_result:
        raise Exception("'service stop' raised: {0}".format(stop_result['exc']))
    if stop_result.get('rc', 1) != 0:
        raise Exception("'service stop' returned rc={0}:\n{1}\n{2}".format(
            stop_result.get('rc'), stop_result.get('out'), stop_result.get('err')))
    print_ok("'service stop' returned 0")

    if service_pid() != 0:
        raise Exception("SCM still reports a PID for the service after stop")
    print_ok("SCM reports service stopped")

    print_ok("OK")
finally:
    uninstall_quietly()
    if root:
        root.cleanup()
