#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that client gets a timeout if there is no
# server.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, SocketPair, print_ok
import socket, ssl

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client'])

    # client should fail to connect since nothing is listening on 13002
    try:
      pair = SocketPair('client', 13001, 13002)
      raise Exception('client should have failed to connect')
    except socket.timeout:
      print_ok("timeout when nothing is listening on 13000")

    # Step 4: client should connect
    pair = SocketPair('client', 13001, 13000)
    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
