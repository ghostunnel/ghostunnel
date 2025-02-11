#!/usr/bin/env python3

"""
Ensures when client disconnects that the server connection also disconnects, with UNIX sockets.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, UnixClient, TlsServer, print_ok, run_ghostunnel, terminate

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        client = UnixClient()
        ghostunnel = run_ghostunnel(['client',
                                     '--listen=unix:{0}'.format(client.get_socket_path()),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--cert=client.crt',
                                     '--key=client.key',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt'])

        # connect to server, confirm that the tunnel is up
        pair = SocketPair(client, TlsServer('server', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        pair = SocketPair(client, TlsServer('server', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "2: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "2: server -> client")
        pair.validate_half_closing_client_closes_server(
            "2: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
