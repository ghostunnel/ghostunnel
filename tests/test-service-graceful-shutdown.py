#!/usr/bin/env python3

"""
Tests graceful shutdown with connection draining on Windows.

Verifies that an in-flight connection can complete after shutdown is
triggered via the /_shutdown HTTP endpoint, and that ghostunnel exits
cleanly with code 0.

Note: this exercises the same shutdownFunc() that the Windows SCM stop
handler invokes via serviceStopCh, but the trigger mechanism here is
/_shutdown (not the SCM). A full SCM-triggered test would require a real
ghostunnel.exe binary rather than the coverage-instrumented test binary.
"""

import http.client
import time
import urllib.request

from common import (LOCALHOST, LISTEN_PORT, STATUS_PORT, TARGET_PORT,
                    RootCert, SocketPair, TcpServer, TlsClient, print_ok,
                    require_platform, run_ghostunnel, terminate, urlopen)

require_platform('Windows')

ghostunnel = None
root = None
try:
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--enable-shutdown',
                                 '--shutdown-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # Establish a connection before shutdown
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "send before shutdown")

    # Trigger graceful shutdown
    print_ok("triggering shutdown via /_shutdown")
    try:
        urlopen(urllib.request.Request(
            "https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT),
            method='POST'))
    except http.client.RemoteDisconnected:
        pass  # expected: server may close before sending response

    # Verify in-flight connection can still complete
    pair.validate_can_send_from_server("world", "send after shutdown triggered")
    pair.validate_closing_client_closes_server("drain completes")

    # Wait for ghostunnel to exit
    stopped = False
    for _ in range(90):
        try:
            ghostunnel.wait(timeout=1)
        except Exception:
            pass
        if ghostunnel.poll() is not None:
            stopped = True
            break
        time.sleep(1)

    if not stopped:
        raise Exception('ghostunnel did not terminate within 90 seconds')

    if ghostunnel.returncode != 0:
        raise Exception(
            'ghostunnel terminated with non-zero exit code: {0}'.format(
                ghostunnel.returncode))

    print_ok("OK (terminated)")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
