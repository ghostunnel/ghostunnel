#!/usr/bin/env python3

# Creates a ghostunnel. Ensures client1 can connect but that clients with
# ou=client2 or ca=other_root can't connect.

from subprocess import Popen
from common import *
import socket
import ssl

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client1')
        root.create_signed_cert('client2')

        other_root = RootCert('other_root')
        other_root.create_signed_cert('other_client1')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt',
                                     '--allow-ou=client1'])

        # connect with client1, confirm that the tunnel is up
        pair = SocketPair(
            TlsClient('client1', 'root', 13001), TcpServer(13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # connect with client2, confirm that the tunnel isn't up
        try:
            pair = SocketPair(
                TlsClient('client2', 'root', 13001), TcpServer(13002))
            raise Exception('failed to reject client2')
        except ssl.SSLError:
            print_ok("client2 correctly rejected")

        # connect with other_client1, confirm that the tunnel isn't up
        try:
            pair = SocketPair(
                TlsClient('other_client1', 'root', 13001), TcpServer(13002))
            raise Exception('failed to reject other_client1')
        except ssl.SSLError:
            print_ok("other_client1 correctly rejected")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
