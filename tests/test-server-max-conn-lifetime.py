#!/usr/bin/env python3

"""
Simulates a hanging connection, waits for timeout.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TlsClient, TcpServer, SocketPair, print_ok, run_ghostunnel, terminate, urlopen, LISTEN_PORT, TARGET_PORT
import time
import json

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('new_server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--connect-timeout=10s',
                                 '--max-conn-lifetime=1s',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # create connections with client, leave connection open
    pair1 = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")

    # check metrics for connection lifetime timeout
    timeout = False
    for _ in range(20):
        metrics = json.loads(str(urlopen(
            "https://{0}:{1}/_metrics".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
        timeouts = [m['value']
                    for m in metrics if "conn.timeout" in m['metric']]
        if timeouts[0] > 0:
            print_ok("connection timed out, as expected")
            timeout = True
            break
        time.sleep(1)

    if not timeout:
        raise Exception("socket still appears to be open after timeout")

    print_ok("OK")

finally:
    terminate(ghostunnel)
