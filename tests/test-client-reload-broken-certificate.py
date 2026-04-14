#!/usr/bin/env python3

"""
Ensures that tunnel sees & reloads certificate changes.

There are various cases to take into account:
- tunnel picks up client cert change and connects with new cert.
- tunnel picks up ca change and connects to other_server.
- tunnel picks up client cert change and uses it on the status port.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsClient, TlsServer, print_ok, reload_args, run_ghostunnel, terminate, trigger_reload, LISTEN_PORT, TARGET_PORT
import os

ghostunnel = None
try:
    # create certs
    root1 = RootCert('root1')
    root1.create_signed_cert('server1')
    root1.create_signed_cert('client1')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client1.p12',
                                 '--cacert=root1.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args())

    # ensure ghostunnel connects with server1
    pair1 = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
        'server1', 'root1', TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_client_cert("client1", "pair1: ou=client1 -> ...")

    # check certificate on status port
    TlsClient(None, 'root1', STATUS_PORT).connect(20, 'client1')
    print_ok("got client1 on /_status")

    # replace keystore with invalid/empty file and reload
    open('new_client1.p12', 'ab').close()
    os.replace('new_client1.p12', 'client1.p12')
    trigger_reload(ghostunnel)

    # should still be using old cert
    TlsClient(None, 'root1', STATUS_PORT).connect(20, 'client1')
    print_ok("reload done")

    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
        'server1', 'root1', TARGET_PORT))
    pair2.validate_can_send_from_client("toto", "pair2 works")
    pair2.validate_client_cert("client1", "pair2: ou=client1 -> ...")
    pair2.cleanup()

    # ensure that pair1 is still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")
    pair1.cleanup()
    print_ok("OK")

finally:
    terminate(ghostunnel)
