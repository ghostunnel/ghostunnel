#!/usr/bin/env python3

"""
Test to check --allow-ip flag behavior (and the hidden --allow-ip-san alias).
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
            san='IP:127.0.0.1,IP:::1,DNS:localhost')
    # client1: contains 127.0.0.1 in its IP SANs (matches --allow-ip=127.0.0.1)
    root.create_signed_cert(
            'client1',
            san='IP:127.0.0.1,DNS:localhost')
    # client2: only has IP:192.0.2.99 (TEST-NET-1), no 127.0.0.1
    root.create_signed_cert(
            'client2',
            san='IP:192.0.2.99,DNS:localhost')

    # start ghostunnel with --allow-ip=127.0.0.1
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ip=127.0.0.1',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # client1 (IP SAN 127.0.0.1) should be accepted
    pair1 = SocketPair(
            TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_can_send_from_server("toto", "pair1 works")
    pair1.cleanup()

    # client2 (IP SAN 192.0.2.99 only) should be rejected
    assert_connection_rejected(
        TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT), "client2")

    terminate(ghostunnel)
    ghostunnel = None

    # Repeat with the hidden alias --allow-ip-san to lock in back-compat
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ip-san=127.0.0.1',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    pair1b = SocketPair(
            TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1b.validate_can_send_from_client("toto", "pair1b works (alias)")
    pair1b.validate_can_send_from_server("toto", "pair1b works (alias)")
    pair1b.cleanup()

    assert_connection_rejected(
        TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT), "client2 (alias)")

    print_ok("OK")
finally:
    terminate(ghostunnel)
