#!/usr/bin/env python3

"""
Tests standalone 'service start' and 'service stop' commands, including
edge cases: stopping an already-stopped service (idempotent) and starting
an already-running service (error).

Requires Windows and Administrator privileges.
"""

import os
import subprocess
import sys

from common import (LOCALHOST, LISTEN_PORT, TARGET_PORT, assert_not_zero,
                    create_default_certs, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-startstop'

root = None


def run_service_cmd(args):
    """Run a ghostunnel service subcommand and return (returncode, stdout, stderr)."""
    proc = run_ghostunnel(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    return proc.returncode, stdout.decode(), stderr.decode()


try:
    root = create_default_certs()

    # Clean up any leftover service from a previous crashed test run.
    proc = run_ghostunnel(
        ['service', 'uninstall', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate(timeout=10)

    # Use absolute paths so the SCM-started service process can find certs
    # regardless of its working directory.
    keystore = os.path.abspath('server.p12')
    cacert = os.path.abspath('root.crt')

    # 1. Install service (auto-starts).
    rc, stdout, stderr = run_service_cmd([
        'service', 'install', '--service-name', SERVICE_NAME,
        '--', 'server',
        '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--keystore={0}'.format(keystore),
        '--cacert={0}'.format(cacert),
        '--allow-ou=client',
    ])
    if rc != 0:
        print("install output:\nstdout: {0}\nstderr: {1}".format(
            stdout, stderr), file=sys.stderr)
        raise Exception("service install failed (rc={0})".format(rc))
    print_ok("install: OK")

    # 2. Stop via 'service stop'.
    rc, stdout, stderr = run_service_cmd([
        'service', 'stop', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("stop failed (rc={0}): {1}".format(rc, stderr))
    print_ok("stop: OK")

    # 3. Verify status reports stopped.
    rc, stdout, stderr = run_service_cmd([
        'service', 'status', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("status failed (rc={0}): {1}".format(rc, stderr))
    if 'stopped' not in stdout.lower():
        raise Exception("expected 'stopped' in status output: {0}".format(stdout))
    print_ok("status after stop: OK (stopped)")

    # 4. Stop again -- should succeed (already stopped).
    rc, stdout, stderr = run_service_cmd([
        'service', 'stop', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("stop-when-stopped failed (rc={0}): {1}".format(rc, stderr))
    print_ok("stop when already stopped: OK (idempotent)")

    # 5. Start via 'service start'.
    rc, stdout, stderr = run_service_cmd([
        'service', 'start', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("start failed (rc={0}): {1}".format(rc, stderr))
    print_ok("start: OK")

    # 6. Verify status reports running.
    rc, stdout, stderr = run_service_cmd([
        'service', 'status', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("status failed (rc={0}): {1}".format(rc, stderr))
    if 'running' not in stdout.lower():
        raise Exception("expected 'running' in status output: {0}".format(stdout))
    print_ok("status after start: OK (running)")

    # 7. Start again -- should fail (already running).
    proc = run_ghostunnel(
        ['service', 'start', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert_not_zero(proc)
    print_ok("start when already running: correctly rejected")

    print_ok("OK")
finally:
    # Best-effort cleanup.
    try:
        proc = run_ghostunnel(
            ['service', 'stop', '--service-name', SERVICE_NAME],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(timeout=10)
    except Exception:
        pass
    try:
        proc = run_ghostunnel(
            ['service', 'uninstall', '--service-name', SERVICE_NAME],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(timeout=10)
    except Exception:
        pass
    if root:
        root.cleanup()
