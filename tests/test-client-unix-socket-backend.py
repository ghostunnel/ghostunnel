#!/usr/bin/env python3

# Creates a ghostunnel. Ensures ghostunnel can listen on a unix socket.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, STATUS_PORT, SocketPair, print_ok, TlsServer, UnixClient
import socket, ssl, tempfile, os

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    socket = UnixClient()
    ghostunnel = Popen(['../ghostunnel', 'client', '--listen=unix:{0}'.format(socket.get_socket_path()),
      '--target={0}:13005'.format(LOCALHOST), '--keystore=client.p12',
      '--cacert=root.crt', '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # connect with client, confirm that the tunnel is up
    pair = SocketPair(socket, TlsServer('server', 'root', 13005))

    pair.validate_can_send_from_server("hello world", "1: server -> client")
    pair.validate_can_send_from_client("hello world", "1: client -> server")
    pair.validate_closing_server_closes_client("1: server closed -> client closed")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
