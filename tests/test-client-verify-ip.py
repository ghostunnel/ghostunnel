#!/usr/bin/env python3

"""
Tests that --verify-ip flag works correctly on the client
(and the hidden --verify-ip-san alias).
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
                   TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
                   assert_connection_rejected

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')
    # server1: has IP SAN 127.0.0.1 (matches --verify-ip=127.0.0.1)
    root.create_signed_cert(
            'server1',
            san='IP:127.0.0.1,DNS:localhost')
    # server2: only has IP SAN 192.0.2.99 (no 127.0.0.1)
    root.create_signed_cert(
            'server2',
            san='IP:192.0.2.99,DNS:localhost')

    # start ghostunnel with --verify-ip=127.0.0.1
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target=localhost:{0}'.format(TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--verify-ip=127.0.0.1',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # connect to server1 (IP SAN 127.0.0.1), should succeed
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
        'server1', 'root', TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # connect to server2 (no matching IP SAN), should be rejected
    assert_connection_rejected(
        TcpClient(LISTEN_PORT), TlsServer('server2', 'root', TARGET_PORT),
        "server2", timeout_ok=False)

    terminate(ghostunnel)
    ghostunnel = None

    # Repeat with the hidden alias --verify-ip-san to lock in back-compat
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target=localhost:{0}'.format(TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--verify-ip-san=127.0.0.1',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
        'server1', 'root', TARGET_PORT))
    pair2.validate_can_send_from_client(
        "hello world", "2: client -> server (alias)")
    pair2.validate_can_send_from_server(
        "hello world", "2: server -> client (alias)")
    pair2.validate_closing_client_closes_server(
        "2: client closed -> server closed (alias)")

    assert_connection_rejected(
        TcpClient(LISTEN_PORT), TlsServer('server2', 'root', TARGET_PORT),
        "server2 (alias)", timeout_ok=False)

    print_ok("OK")
finally:
    terminate(ghostunnel)
