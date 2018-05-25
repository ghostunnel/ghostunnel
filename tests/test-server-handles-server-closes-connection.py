#!/usr/bin/env python3

# Creates a ghostunnel. Ensures when server disconnects that the client
# connection also disconnects.

from common import *

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13000'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt',
                                     '--allow-ou=client'])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13000))
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_closing_server_closes_client(
            "1: server closed -> client closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
