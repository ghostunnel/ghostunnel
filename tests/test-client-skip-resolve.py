#!/usr/bin/env python3

"""
Ensures --skip-resolve lets ghostunnel start with an unresolvable target
(e.g. before the network is up) and that without --skip-resolve ghostunnel
fails fast with a resolution error.

Covers socket.ParseAddress(..., skipResolve=true) via the real CLI and the
documented startup-ordering contract for --skip-resolve.
"""

from common import (
    LOCALHOST,
    LISTEN_PORT,
    STATUS_PORT,
    RootCert,
    TcpClient,
    print_ok,
    run_ghostunnel,
    terminate,
    wait_for_status,
)

import subprocess

# Use a syntactically valid hostname guaranteed not to resolve. The
# ".invalid" TLD is reserved (RFC 2606) and must never resolve in DNS.
UNRESOLVABLE_TARGET = 'does-not-exist-x9q3.invalid:13000'

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # ===== Case 1: --skip-resolve allows startup with an unresolvable target =====
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}'.format(UNRESOLVABLE_TARGET),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--skip-resolve',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # block until ghostunnel status port is up; if process exited the test fails
    TcpClient(STATUS_PORT).connect(20)

    # process must still be running (didn't fail on resolve)
    if ghostunnel.poll() is not None:
        raise Exception("ghostunnel exited unexpectedly with code {0} when --skip-resolve was set".format(
            ghostunnel.returncode))

    # /_status should report backend critical (target cannot be reached / resolved)
    # but the listener itself should be up. The handler reports ok=False when
    # the backend dial fails.
    info = wait_for_status(lambda i: i.get('listen_address') is not None, timeout=10)

    if info.get('ok'):
        raise Exception(
            "expected status ok=False with unresolvable target, got: {0}".format(info))
    if info.get('backend_ok'):
        raise Exception(
            "expected backend_ok=False with unresolvable target, got: {0}".format(info))
    if info.get('backend_status') != 'critical':
        raise Exception(
            "expected backend_status='critical', got: {0}".format(info))
    if UNRESOLVABLE_TARGET not in info.get('forward_address', ''):
        raise Exception(
            "expected forward_address to include {0}, got: {1}".format(
                UNRESOLVABLE_TARGET, info.get('forward_address')))

    print_ok("ghostunnel started with --skip-resolve despite unresolvable target")

    # gracefully shut down before the second case so STATUS_PORT/LISTEN_PORT free up
    terminate(ghostunnel)
    ghostunnel = None

    # ===== Case 2: Without --skip-resolve, startup must fail =====
    # Capture stderr via PIPE so we can inspect the error message.
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}'.format(UNRESOLVABLE_TARGET),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)],
                                stderr=subprocess.PIPE)

    try:
        stdout_data, stderr_data = ghostunnel.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        ghostunnel.kill()
        raise Exception("ghostunnel did not exit within 30s without --skip-resolve "
                        "(expected immediate resolution failure)")

    if ghostunnel.returncode == 0:
        raise Exception("ghostunnel exited with code 0 but should have failed "
                        "to resolve {0}".format(UNRESOLVABLE_TARGET))

    stderr_text = (stderr_data or b'').decode('utf-8', errors='replace')
    # The error path logs "error: invalid target address: ...". The wrapped
    # net.ResolveTCPAddr error mentions the unresolved host or "no such host".
    lowered = stderr_text.lower()
    if 'invalid target address' not in lowered and 'no such host' not in lowered \
            and 'lookup' not in lowered:
        raise Exception(
            "expected a resolution error message in stderr, got: {0}".format(stderr_text))

    print_ok("ghostunnel correctly refused to start without --skip-resolve "
             "(exit={0})".format(ghostunnel.returncode))
    ghostunnel = None  # already exited

    print_ok("OK")
finally:
    if ghostunnel is not None:
        terminate(ghostunnel)
