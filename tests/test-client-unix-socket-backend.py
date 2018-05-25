#!/usr/bin/env python3

# Creates a ghostunnel. Ensures ghostunnel can listen on a unix socket.

from subprocess import Popen
from common import *
import socket
import ssl
import tempfile
import os
import os.path

if __name__ == "__main__":
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
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client.p12',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(socket, TlsServer('server', 'root', 13002))
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
