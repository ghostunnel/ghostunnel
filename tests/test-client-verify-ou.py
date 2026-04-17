#!/usr/bin/env python3

"""
Tests that --verify-ou flag works correctly on the client.

Note: create_signed_cert(name) sets both CN and OU to the given name,
so --verify-ou=server1 checks the OU field of the server certificate.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
                   TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
                   assert_connection_rejected

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')
    root.create_signed_cert(
            'server1',
            san='IP:127.0.0.1,IP:::1,DNS:localhost')
    root.create_signed_cert(
            'server2',
            san='IP:127.0.0.1,IP:::1,DNS:localhost')

    # start ghostunnel with --verify-ou=server1
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target=localhost:{0}'.format(TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--verify-ou=server1',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # connect to server1 (OU=server1), should succeed
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
        'server1', 'root', TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # connect to server2 (OU=server2), should be rejected
    assert_connection_rejected(
        TcpClient(LISTEN_PORT), TlsServer('server2', 'root', TARGET_PORT),
        "server2", timeout_ok=False)

    print_ok("OK")
finally:
    terminate(ghostunnel)
