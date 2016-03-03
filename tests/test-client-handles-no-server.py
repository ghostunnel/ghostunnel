#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that client gets a timeout if there is no
# server.

from subprocess import Popen
from test_common import *
import socket, ssl

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['client', '--listen={0}:13004'.format(LOCALHOST),
      '--target={0}:13005'.format(LOCALHOST), '--keystore=client.p12',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT), '--cacert=root.crt'])

    # client should fail to connect since nothing is listening on 13006
    try:
      pair = SocketPair(TcpClient(13004), TlsServer('server', 'root', 13006))
      raise Exception('client should have failed to connect')
    except socket.timeout:
      print_ok("timeout when nothing is listening on 13006")

    # client should connect
    pair = SocketPair(TcpClient(13004), TlsServer('server', 'root', 13005))
    pair.cleanup()
    print_ok("OK")
  finally:
    terminate(ghostunnel)
      
