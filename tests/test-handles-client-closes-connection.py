#!/usr/local/bin/python

# Creates a ghostunnel. Ensures when client disconnects that the server
# connection also disconnects.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import socket, ssl

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    # root, ou=server, ou=client, ou=other_client
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('client1', 'root')

    # Step 2: start ghostunnel
    #ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
    #  '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
    #  '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])
    ghostunnel = Popen(['/usr/local/Cellar/stunnel/5.23/bin/stunnel', 'stunnel-1.conf'])

    # Step 3: connect with client1, confirm that the tunnel is up
    pair = SocketPair('client1', 13001, 13000)
    pair.validate_can_send_from_client("hello world", "1: client -> server")
    pair.validate_can_send_from_server("hello world", "1: server -> client")
    pair.validate_closing_client_closes_server("1: client closed -> server closed")

    print_ok("OK")
  finally:
    cleanup_certs(['root', 'server', 'client1'])
    if ghostunnel:
      ghostunnel.kill()
