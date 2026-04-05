#!/usr/bin/env python3

"""
Tests that verify-dns flag works correctly on the client.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
                   TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
                   assert_connection_rejected

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')
        root.create_signed_cert(
                'server1',
                san='DNS:server1,IP:127.0.0.1,IP:::1,DNS:localhost')
        root.create_signed_cert(
                'server2',
                san='DNS:server2,IP:127.0.0.1,IP:::1,DNS:localhost')

        other_root = RootCert('other_root')
        other_root.create_signed_cert('other_server')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target=localhost:{0}'.format(TARGET_PORT),
                                     '--keystore=client.p12',
                                     '--verify-dns=server1',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect to server1, confirm that the tunnel is up
        pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
            'server1', 'root', TARGET_PORT))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # connect to server2, confirm that the tunnel isn't up
        assert_connection_rejected(
            TcpClient(LISTEN_PORT), TlsServer('server2', 'root', TARGET_PORT), "server2")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
