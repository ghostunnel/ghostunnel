#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsClient, TlsServer, print_ok, run_ghostunnel, terminate, urlopen, LISTEN_PORT, TARGET_PORT
import http.client
import urllib.request
import urllib.error
import urllib.parse
import time
import os

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--enable-shutdown',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'client')

    # create connections with client
    pair1 = SocketPair(
        TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.cleanup()

    print_ok('attempting to terminate ghostunnel via HTTP POST')
    try:
        urlopen(urllib.request.Request("https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT), method='POST'))
    except http.client.RemoteDisconnected:
        pass  # expected: server may close before sending response

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

    if ghostunnel.returncode != 0:
        raise Exception(
            'ghostunnel terminated with non-zero exit code: {0}'.format(
                ghostunnel.returncode))

    print_ok("OK (terminated)")
finally:
    terminate(ghostunnel)
