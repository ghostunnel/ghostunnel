#!/usr/bin/env python3

"""
Ensures ghostunnel can listen on a unix socket.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TlsServer, UnixClient, print_ok, run_ghostunnel, require_platform, terminate, TARGET_PORT
import os
import os.path

require_platform('Darwin', 'Linux', 'BSD')

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    socket = UnixClient()
    ghostunnel = run_ghostunnel(['client',
                                 '--listen=unix:{0}'.format(socket.get_socket_path()),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # connect with client, confirm that the tunnel is up
    pair = SocketPair(socket, TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_closing_server_closes_client(
        "1: server closed -> client closed")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if os.path.exists(socket.get_socket_path()):
        raise Exception('failed to clean up unix socket')
