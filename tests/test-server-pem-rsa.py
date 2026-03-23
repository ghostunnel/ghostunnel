#!/usr/bin/env python3

"""
Tests that ghostunnel server mode works with PEM RSA cert/key files.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT

if __name__ == "__main__":
    ghostunnel = None
    try:
        root = RootCert('root', algorithm='rsa')
        root.create_signed_cert('server', p12_password=None)
        root.create_signed_cert('client', p12_password=None)

        # start ghostunnel with PEM RSA cert/key
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--cert=server.crt',
                                     '--key=server.key',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

        # validate connection
        pair = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_client("hello", "client -> server")
        pair.validate_can_send_from_server("world", "server -> client")
        pair.validate_tunnel_ou("server", "ou=server")
        pair.validate_closing_client_closes_server("client close -> server close")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
