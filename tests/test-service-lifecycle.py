#!/usr/bin/env python3

"""
Tests the full Windows service lifecycle: install -> start -> status -> stop ->
uninstall -> verify-gone. Requires Windows and Administrator privileges.

The coverage-instrumented binary (built with go build -cover) is a real
ghostunnel binary, so the SCM can start it as a Windows service.
"""

import subprocess
import sys

from common import (LOCALHOST, LISTEN_PORT, TARGET_PORT, assert_not_zero,
                    print_ok, require_admin, require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-lifecycle'


def run_service_cmd(args):
    """Run a ghostunnel service subcommand and return (returncode, stdout, stderr)."""
    proc = run_ghostunnel(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    return proc.returncode, stdout.decode(), stderr.decode()


try:
    # Clean up any leftover service from a previous crashed test run.
    # If the service doesn't exist, this fails silently.
    proc = run_ghostunnel(
        ['service', 'uninstall', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate(timeout=10)

    # 1. Install and start service.
    rc, stdout, stderr = run_service_cmd([
        'service', 'install', '--service-name', SERVICE_NAME,
        '--', 'server',
        '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--keystore=server.p12',
        '--cacert=root.crt',
        '--allow-ou=client',
    ])
    combined = stdout + stderr
    if rc != 0:
        print("unexpected install output:\nstdout: {0}\nstderr: {1}".format(
            stdout, stderr), file=sys.stderr)
        raise Exception("service install failed (rc={0})".format(rc))
    if 'installed and started' not in combined.lower():
        print("unexpected install output:\nstdout: {0}\nstderr: {1}".format(
            stdout, stderr), file=sys.stderr)
        raise Exception("service install did not produce expected output")
    print_ok("install: OK (installed and started)")

    # 2. Status should succeed (service is registered).
    rc, stdout, stderr = run_service_cmd([
        'service', 'status', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("status failed (rc={0}): {1}".format(rc, stdout))
    if SERVICE_NAME not in stdout:
        raise Exception("status output missing service name: {0}".format(stdout))
    print_ok("status: OK ({0})".format(stdout.strip()))

    # 3. Stop the running service.
    rc, stdout, stderr = run_service_cmd([
        'service', 'stop', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("stop failed (rc={0}): {1}".format(rc, stdout))
    print_ok("stop: OK")

    # 4. Uninstall.
    rc, stdout, stderr = run_service_cmd([
        'service', 'uninstall', '--service-name', SERVICE_NAME,
    ])
    if rc != 0:
        raise Exception("uninstall failed (rc={0}): {1}".format(rc, stdout))
    if 'removed' not in stdout.lower():
        raise Exception("uninstall output missing 'removed': {0}".format(stdout))
    print_ok("uninstall: OK")

    # 5. Status should fail now (service is gone).
    proc = run_ghostunnel(
        ['service', 'status', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert_not_zero(proc)
    print_ok("status after uninstall: correctly reports error")

    print_ok("OK")
finally:
    # Best-effort cleanup in case the test failed partway through.
    try:
        proc = run_ghostunnel(
            ['service', 'uninstall', '--service-name', SERVICE_NAME],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.wait(timeout=10)
    except Exception:
        pass
