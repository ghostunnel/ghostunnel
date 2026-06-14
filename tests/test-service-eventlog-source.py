#!/usr/bin/env python3

"""
Verifies that --eventlog runtime entries land on the Event Log source matching
the installed service name (i.e. the source that 'service install' registered),
rather than a hardcoded fallback. Requires Windows and Administrator privileges.

Regression test for the case where 'service install --service-name foo' would
register source 'foo' but the running service would write to source 'ghostunnel',
producing "description not found" entries in Event Viewer under the wrong source.
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


def query_eventlog_messages():
    """Return concatenated messages from up to 10 most recent entries under
    SERVICE_NAME in the Application log, or '' if none. Uses Get-EventLog
    (classic API) which filters by Source property directly without depending
    on the provider-discovery cache that Get-WinEvent -FilterHashtable uses."""
    ps_cmd = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-EventLog -LogName Application -Source '{0}' -Newest 10 | "
        "Select-Object -ExpandProperty Message"
    ).format(SERVICE_NAME)
    ps = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=30)
    return (ps.stdout or '').strip()


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

    # Poll for events. Newly-registered sources can take a few seconds before
    # the Event Log service reflects them in queries.
    messages = ''
    for _ in range(30):
        messages = query_eventlog_messages()
        if messages:
            break
        time.sleep(1)

    if not messages:
        raise Exception(
            "no Event Log entries under Source={0} after 30s; runtime logger "
            "is writing to a different source".format(SERVICE_NAME))
    print_ok("event log entries present under Source={0}".format(SERVICE_NAME))

    # The "description not found" placeholder indicates the source was not
    # registered with a message file at install time. With B1 fixed AND the
    # install code actually calling InstallAsEventCreate, entries should
    # render normally.
    if 'description for Event ID' in messages:
        raise Exception(
            "entries under Source={0} show 'description not found':\n{1}".format(
                SERVICE_NAME, messages[:500]))
    print_ok("entries render without 'description not found'")

    print_ok("OK")
finally:
    uninstall_quietly()
    if root:
        root.cleanup()
