#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that client gets a timeout if there is no
# server.

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

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])

    # Step 3: client should fail to connect since nothing is listening on 13002
    try:
      pair = SocketPair('client1', 13001, 13002)
    except socket.timeout:
      print_ok("timeout when nothing is listening on 13000")

    # Step 4: client should connect
    try:
      pair = SocketPair('client1', 13001, 13000)
    except socket.timeout:
      print_ok("timeout when nothing is listening on 13000")

    print_ok("OK")
  finally:
    cleanup_certs(['root', 'server', 'client1'])
    if ghostunnel:
      ghostunnel.kill()
