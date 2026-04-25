#!/usr/bin/env python3

"""
Tests that ghostunnel refuses to start or stop a service it did not install.
Creates a dummy service via sc.exe, then verifies that 'service start' and
'service stop' both reject it because the GhostunnelManaged registry marker
is missing. Requires Windows and Administrator privileges.
"""

import subprocess
import sys

from common import (print_ok, require_admin, require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-foreign-ss'

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

    # Attempt to start it via ghostunnel -- should be refused.
    proc = run_ghostunnel(
        ['service', 'start', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    combined = (stdout + stderr).decode()

    if proc.returncode == 0:
        raise Exception("expected non-zero exit code for foreign service start")
    if 'not' not in combined.lower() or 'ghostunnel' not in combined.lower():
        print("unexpected output: {0!r}".format(combined), file=sys.stderr)
        raise Exception(
            "expected 'not managed by ghostunnel' error, got: {0}".format(combined))
    print_ok("start correctly refused for foreign service")

    # Attempt to stop it via ghostunnel -- should be refused.
    proc = run_ghostunnel(
        ['service', 'stop', '--service-name', SERVICE_NAME],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    combined = (stdout + stderr).decode()

    if proc.returncode == 0:
        raise Exception("expected non-zero exit code for foreign service stop")
    if 'not' not in combined.lower() or 'ghostunnel' not in combined.lower():
        print("unexpected output: {0!r}".format(combined), file=sys.stderr)
        raise Exception(
            "expected 'not managed by ghostunnel' error, got: {0}".format(combined))
    print_ok("stop correctly refused for foreign service")

    print_ok("OK")
finally:
    # Clean up the dummy service.
    try:
        subprocess.call(['sc.exe', 'delete', SERVICE_NAME],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
