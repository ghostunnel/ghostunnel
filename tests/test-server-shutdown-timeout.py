#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, skip_on_windows, terminate, LISTEN_PORT, TARGET_PORT
import time
import os

skip_on_windows("SIGTERM not supported")

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--shutdown-timeout=1s',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # create connections with client
    pair1 = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")

    # shut down ghostunnel with connection open, make sure it doesn't hang
    print_ok('attempting to terminate ghostunnel via SIGTERM signals')
    ghostunnel.terminate()

    stopped = False
    for _ in range(90):
        try:
            ghostunnel.wait(timeout=1)
        except Exception:
            pass  # wait() may raise if process hasn't exited yet
        if ghostunnel.poll() is not None:
            stopped = True
            break
        print_ok("ghostunnel is still alive")
        time.sleep(1)

    if not stopped:
        raise Exception('ghostunnel did not terminate within 90 seconds')

    # We expect retv != 0 because of timeout
    if ghostunnel.returncode == 0:
        raise Exception(
            'ghostunnel terminated gracefully instead of timing out?')

    print_ok("OK (terminated)")
finally:
    terminate(ghostunnel)
