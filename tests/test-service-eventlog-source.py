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

# Anchor on a unique-to-this-run message so the assertion can't latch onto
# stale events from a prior install/uninstall with the same source name.
LISTEN_MSG_FRAGMENT = '{0}:{1}'.format(LOCALHOST, LISTEN_PORT)

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


def query_eventlog(source):
    """Return concatenated messages from up to 10 most recent entries under
    `source` in the Application log, or '' if none. Uses Get-EventLog (classic
    API) which filters by Source property directly without depending on the
    provider-discovery cache that Get-WinEvent -FilterHashtable uses."""
    ps_cmd = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-EventLog -LogName Application -Source '{0}' -Newest 10 | "
        "Select-Object -ExpandProperty Message"
    ).format(source)
    ps = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=30)
    return (ps.stdout or '').strip()


def diagnostic_dump():
    """On failure, dump the most recent Application events whose source
    contains 'ghostunnel'. Helps diagnose whether events landed under a
    different source name."""
    # The {0}/{1} below are PowerShell -f placeholders, not Python format
    # placeholders; the string is passed through to powershell.exe verbatim.
    ps_cmd = (
        "$ErrorActionPreference='SilentlyContinue'; "
        "Get-EventLog -LogName Application -Newest 50 | "
        "Where-Object { $_.Source -like '*ghostunnel*' } | "
        "ForEach-Object { '[Source={0}] {1}' -f $_.Source, $_.Message } "
    )
    ps = subprocess.run(
        ['powershell.exe', '-NoProfile', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=30)
    print("--- diagnostic: recent Application events with 'ghostunnel' in source ---",
          file=sys.stderr)
    print(ps.stdout or '(none)', file=sys.stderr)
    print("--- end diagnostic ---", file=sys.stderr)


try:
    root = create_default_certs()
    keystore = os.path.abspath('server.p12')
    cacert = os.path.abspath('root.crt')

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

    # Poll for events containing our unique listen-address fragment. Newly-
    # registered sources can take a few seconds before the Event Log service
    # reflects them in queries; anchoring on the listen address ignores stale
    # entries from prior runs of the same source.
    messages = ''
    found_listen = False
    for _ in range(30):
        messages = query_eventlog(SERVICE_NAME)
        if LISTEN_MSG_FRAGMENT in messages:
            found_listen = True
            break
        time.sleep(1)

    if not found_listen:
        diagnostic_dump()
        if not messages:
            raise Exception(
                "no Event Log entries under Source={0} after 30s".format(
                    SERVICE_NAME))
        raise Exception(
            "no entry containing {0!r} under Source={1} after 30s; got:\n{2}".format(
                LISTEN_MSG_FRAGMENT, SERVICE_NAME, messages[:500]))
    print_ok("event log entry for this run found under Source={0}".format(
        SERVICE_NAME))

    if 'description for Event ID' in messages:
        diagnostic_dump()
        raise Exception(
            "entries under Source={0} show 'description not found':\n{1}".format(
                SERVICE_NAME, messages[:500]))
    print_ok("entries render without 'description not found'")

    print_ok("OK")
finally:
    uninstall_quietly()
    if root:
        root.cleanup()
