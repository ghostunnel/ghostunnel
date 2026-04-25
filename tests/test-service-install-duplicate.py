#!/usr/bin/env python3

"""
Tests that installing a service with a name that already exists fails
with a non-zero exit code. Requires Windows and Administrator privileges.
"""

import os
import subprocess
import sys

from common import (LOCALHOST, LISTEN_PORT, TARGET_PORT, assert_not_zero,
                    create_default_certs, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-duplicate'

root = None


def run_service_cmd(args):
    """Run a ghostunnel service subcommand and return (returncode, stdout, stderr)."""
    proc = run_ghostunnel(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    return proc.returncode, stdout.decode(), stderr.decode()


try:
    root = create_default_certs()

    # Use absolute paths so the SCM-started service process can find certs
    # regardless of its working directory.
    keystore = os.path.abspath('server.p12')
    cacert = os.path.abspath('root.crt')

    INSTALL_ARGS = [
        'service', 'install', '--service-name', SERVICE_NAME,
        '--', 'server',
        '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--keystore={0}'.format(keystore),
        '--cacert={0}'.format(cacert),
        '--allow-ou=client',
    ]

    # Clean up any leftover service from a previous crashed test run.
    proc = run_ghostunnel(
        ['service', 'uninstall', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.communicate(timeout=10)

    # 1. First install should succeed.
    rc, stdout, stderr = run_service_cmd(INSTALL_ARGS)
    if rc != 0:
        print("install output:\nstdout: {0}\nstderr: {1}".format(
            stdout, stderr), file=sys.stderr)
        raise Exception("first install failed (rc={0})".format(rc))
    print_ok("first install: OK")

    # 2. Second install with same name should fail.
    proc = run_ghostunnel(INSTALL_ARGS,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert_not_zero(proc)
    print_ok("duplicate install: correctly rejected")

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
