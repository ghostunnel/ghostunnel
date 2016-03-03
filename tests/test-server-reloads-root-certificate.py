#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that tunnel sees & reloads a root certificate
# change.

from subprocess import Popen, call
from test_common import *
import socket, ssl, time, signal, os

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client1')
    root.create_signed_cert('client2')

    new_root = RootCert('new_root')
    new_root.create_signed_cert('new_server')
    new_root.create_signed_cert('client3')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client1', '--allow-ou=client2',
      '--allow-ou=client3', '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # create connections with client1 and client2
    pair1 = SocketPair(TlsClient('client1', 'root', 13001), TcpServer(13002))
    pair1.validate_can_send_from_client("toto", "pair1 works")

    pair2 = SocketPair(TlsClient('client2', 'root', 13001), TcpServer(13002))
    pair2.validate_can_send_from_client("toto", "pair2 works")

    # replace keystore and trigger reload
    os.rename('new_root.crt', 'root.crt')
    os.rename('new_server.p12', 'server.p12')
    ghostunnel.send_signal(signal.SIGUSR1)

    # ensure ghostunnel is serving new_server
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'new_server')
    print_ok("reload done")

    # ensure that client3 can connect
    pair3 = SocketPair(TlsClient('client3', 'root', 13001), TcpServer(13002))
    pair3.validate_can_send_from_client("toto", "pair3 works")
    pair3.cleanup()

    # ensure that client2 cannot connect
    try:
      pair4 = SocketPair(TlsClient('client2', 'root', 13001), TcpServer(13002))
      raise Exception('client2 was able to connect')
    except ssl.SSLError:
      print_ok("client2 failed to connect")

    # ensure that pair1 and pair2 are still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")
    pair2.validate_can_send_from_client("toto", "pair2 still works")
    pair1.cleanup()
    pair2.cleanup()

    print_ok("OK")
  finally:
    terminate(ghostunnel)
      
