#!/usr/bin/env python3

"""
Test to check --allow-uri flag behavior.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, \
                   TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
                   assert_connection_rejected

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert(
            'server',
            san='URI:spiffe://server,IP:127.0.0.1,IP:::1,DNS:localhost')
    root.create_signed_cert(
            'client1',
            san='URI:spiffe://client1,IP:127.0.0.1,IP:::1,DNS:localhost')
    root.create_signed_cert(
            'client2',
            san='URI:spiffe://client2,IP:127.0.0.1,IP:::1,DNS:localhost')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-uri=spiffe://client1',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # create connections with client
    pair1 = SocketPair(
            TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_can_send_from_server("toto", "pair1 works")

    assert_connection_rejected(
        TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT), "client2")

    print_ok("OK")
finally:
    terminate(ghostunnel)
