#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that client gets a timeout if there is no
# server.

from subprocess import Popen
from common import *
import socket, ssl

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['client',
      '--proxy={0}:13001:{0}:13002'.format(LOCALHOST),
      '--keystore=client.p12',
      '--cacert=root.crt',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # client should fail to connect since nothing is listening on 13003
    try:
      pair = SocketPair(TcpClient(13001), TlsServer('server', 'root', 13003))
      raise Exception('client should have failed to connect')
    except socket.timeout:
      print_ok("timeout when nothing is listening on 13003")

    # client should connect
    pair = SocketPair(TcpClient(13001), TlsServer('server', 'root', 13002))
    pair.cleanup()
    print_ok("OK")
  finally:
    terminate(ghostunnel)
      
