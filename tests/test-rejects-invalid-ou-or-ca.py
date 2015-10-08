#!/usr/local/bin/python

# Creates a ghostunnel. Ensures client1 can connect but that clients with
# ou=client2 or ca=other_root can't connect.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import socket, ssl

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('client1', 'root')
    create_signed_cert('client2', 'root')

    create_root_cert('other_root')
    create_signed_cert('other_client1', 'other_root')

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])

    # Step 3: connect with client1, confirm that the tunnel is up
    pair = SocketPair('client1', 13001, 13000)
    pair.validate_can_send_from_client("hello world", "1: client -> server")
    pair.validate_can_send_from_server("hello world", "1: server -> client")
    pair.validate_closing_client_closes_server("1: client closed -> server closed")

    # Step 4: connect with client2, confirm that the tunnel isn't up
    try:
      pair = SocketPair('client2', 13001, 13000)
      raise Exception('failed to reject client2')
    except socket.timeout:
      # TODO: this should be a ssl.SSLError, but ends up being a timeout. Figure
      # out why.
      print_ok("client2 correctly rejected")

    # Step 5: connect with other_client1, confirm that the tunnel isn't
    # up
    try:
      pair = SocketPair('other_client1', 13001, 13000)
      raise Exception('failed to reject other_client1')
    except ssl.SSLError:
      print_ok("other_client1 correctly rejected")

    print_ok("OK")
  finally:
    cleanup_certs(['root', 'server', 'client1', 'client2', 'other_root', 'other_client1'])
    if ghostunnel:
      ghostunnel.kill()
