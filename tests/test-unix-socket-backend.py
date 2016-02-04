#!/usr/bin/env python3

# Creates a ghostunnel. Ensures when server disconnects that the client
# connection also disconnects.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPairUnix, print_ok, cleanup_certs
import socket, ssl, tempfile, os

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('client1', 'root')

    socket_dir = tempfile.mkdtemp()
    socket_path = os.path.join(socket_dir, 'ghostunnel-test-socket')

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
        '--target=unix:{0}'.format(socket_path), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])

    # Step 3: connect with client1, confirm that the tunnel is up
    pair = SocketPairUnix('client1', 13001, socket_path)
    pair.validate_can_send_from_server("hello world", "1: server -> client")
    pair.validate_can_send_from_client("hello world", "1: client -> server")
    pair.validate_closing_server_closes_client("1: server closed -> client closed")

    os.remove(socket_path)

    pair = SocketPairUnix('client1', 13001, socket_path)
    pair.validate_can_send_from_server("hello world", "1: server -> client")
    pair.validate_can_send_from_client("hello world", "1: client -> server")
    pair.validate_closing_client_closes_server("1: server closed -> client closed")

    print_ok("OK")
  finally:
    cleanup_certs(['root', 'server', 'client1'])
    if ghostunnel:
      ghostunnel.kill()
