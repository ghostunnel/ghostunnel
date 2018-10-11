#!/usr/bin/env python3

"""
Tests that verify-dns flag works correctly on the client.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
                   TlsServer, print_ok, run_ghostunnel, terminate

import ssl

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
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target=localhost:13002',
                                     '--keystore=client.p12',
                                     '--verify-dns=server1',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect to server1, confirm that the tunnel is up
        pair = SocketPair(TcpClient(13001), TlsServer(
            'server1', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # connect to server2, confirm that the tunnel isn't up
        try:
            pair = SocketPair(TcpClient(13001), TlsServer(
                'server2', 'root', 13002))
            raise Exception('failed to reject other_server')
        except ssl.SSLError:
            print_ok("other_server correctly rejected")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
