#!/usr/bin/env python3

"""
Ensures when client disconnects that the server connection also disconnects.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--close-timeout=10s',
                                     '--cacert=root.crt'])

        # connect to server, confirm that the tunnel is up
        pair = SocketPair(TcpClient(13001), TlsServer('server', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        pair = SocketPair(TcpClient(13001), TlsServer('server', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "2: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "2: server -> client")
        pair.validate_half_closing_client_closes_server(
            "2: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
