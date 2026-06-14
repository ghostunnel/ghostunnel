#!/usr/bin/env python3

"""
Verifies that --eventlog runtime entries land on the Event Log source matching
the installed service name (i.e. the source that 'service install' registered),
rather than a hardcoded fallback. Requires Windows and Administrator privileges.

Regression test for the case where 'service install --service-name foo' would
register source 'foo' but the running service would write to source 'ghostunnel',
producing "description not found" entries in Event Viewer.
"""

import os
import subprocess
import sys
import time

from common import (LOCALHOST, LISTEN_PORT, TARGET_PORT, create_default_certs,
                    print_ok, require_admin, require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

SERVICE_NAME = 'ghostunnel-pytest-eventlog'

root = None


def run_service_cmd(args):
    proc = run_ghostunnel(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate(timeout=30)
    return proc.returncode, stdout.decode(), stderr.decode()


def uninstall_quietly():
    try:
        proc = run_ghostunnel(
            ['service', 'uninstall', '--service-name', SERVICE_NAME],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate(timeout=10)
    except Exception:
        pass


try:
    root = create_default_certs()
    keystore = os.path.abspath('server.p12')
    cacert = os.path.abspath('root.crt')

    # Clean slate.
    uninstall_quietly()

    rc, stdout, stderr = run_service_cmd([
        'service', 'install', '--service-name', SERVICE_NAME,
        '--', 'server', '--eventlog',
        '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
        '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
        '--keystore={0}'.format(keystore),
        '--cacert={0}'.format(cacert),
        '--allow-ou=client',
    ])
    if rc != 0:
        print("install failed:\nstdout: {0}\nstderr: {1}".format(stdout, stderr),
              file=sys.stderr)
        raise Exception("service install failed (rc={0})".format(rc))
    print_ok("install: OK")

    # Give the service a moment to emit its startup log lines via --eventlog.
    time.sleep(2)

    # Query the Event Log for entries on the source matching our service name.
    # -ErrorAction SilentlyContinue keeps an empty result from blowing up the
    # cmdlet; we check the count explicitly.
    ps_script = (
        "$events = Get-WinEvent -FilterHashtable @{{LogName='Application'; "
        "ProviderName='{0}'}} -MaxEvents 20 -ErrorAction SilentlyContinue; "
        "if (-not $events) {{ exit 10 }}; "
        "$bad = $events | Where-Object {{ $_.Message -match "
        "'description for Event ID' }}; "
        "if ($bad) {{ $bad | ForEach-Object {{ Write-Output $_.Message }}; "
        "exit 11 }}; "
        "$events | Select-Object -First 1 -ExpandProperty Message"
    ).format(SERVICE_NAME)

    ps = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_script],
        capture_output=True, text=True, timeout=30)

    if ps.returncode == 10:
        raise Exception(
            "no Event Log entries for ProviderName={0}; runtime logger is "
            "writing to a different source".format(SERVICE_NAME))
    if ps.returncode == 11:
        raise Exception(
            "Event Log entries for ProviderName={0} show \"description not "
            "found\":\n{1}".format(SERVICE_NAME, ps.stdout))
    if ps.returncode != 0:
        raise Exception("powershell failed (rc={0}):\nstdout: {1}\nstderr: {2}".format(
            ps.returncode, ps.stdout, ps.stderr))

    print_ok("event log entries render correctly under ProviderName={0}".format(
        SERVICE_NAME))
    print_ok("OK")
finally:
    uninstall_quietly()
    if root:
        root.cleanup()
