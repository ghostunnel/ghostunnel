#!/usr/bin/env python3

"""
Tests that ghostunnel refuses to uninstall a service it did not install.
Creates a dummy service via sc.exe, then verifies ghostunnel's 'service
uninstall' rejects it because the GhostunnelManaged registry marker is
missing. Requires Windows and Administrator privileges.
"""

import subprocess
import sys

from common import (assert_not_zero, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-foreign'

try:
    # Clean up any leftover dummy service from a previous crashed test run.
    subprocess.call(['sc.exe', 'delete', SERVICE_NAME],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Create a dummy service that ghostunnel did not install.
    subprocess.check_call([
        'sc.exe', 'create', SERVICE_NAME,
        'binPath=', 'C:\\Windows\\System32\\cmd.exe',
        'start=', 'demand',
    ])
    print_ok("created dummy service {0}".format(SERVICE_NAME))

    # Attempt to uninstall it via ghostunnel -- should be refused.
    # Errors from run() go through t.Errorf in the Go test harness,
    # which prints to stdout (not stderr) when the test fails.
    ghostunnel = run_ghostunnel(
        ['service', 'uninstall', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = ghostunnel.communicate(timeout=30)
    stdout = stdout.decode()

    if ghostunnel.returncode == 0:
        raise Exception("expected non-zero exit code for foreign service uninstall")

    if 'not' not in stdout.lower() or 'ghostunnel' not in stdout.lower():
        print("unexpected stdout: {0}".format(stdout), file=sys.stderr)
        raise Exception(
            "expected 'not managed by ghostunnel' error, got: {0}".format(stdout))

    print_ok("correctly refused to uninstall foreign service")
    print_ok("OK")
finally:
    # Clean up the dummy service.
    try:
        subprocess.call(['sc.exe', 'delete', SERVICE_NAME],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
