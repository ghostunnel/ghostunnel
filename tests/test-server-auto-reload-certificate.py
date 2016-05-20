#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that tunnel sees & reloads a certificate change.

from subprocess import Popen
from test_common import *
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('new_server')
    root.create_signed_cert('client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client', '--timed-reload=1s',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # create connections with client
    pair1 = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_tunnel_ou("server", "pair1 -> ou=server")

    # Replace keystore and trigger reload
    os.rename('new_server.p12', 'server.p12')
    # NOT reloading explicitly here (should be automatic)

    TlsClient(None, 'root', STATUS_PORT).connect(20, 'new_server')
    print_ok("reload done")

    # create connections with client
    pair2 = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))
    pair2.validate_can_send_from_client("toto", "pair2 works")
    pair2.validate_tunnel_ou("new_server", "pair2 -> ou=new_server")
    pair2.cleanup()

    # ensure that pair1 is still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")
    pair1.cleanup()

    print_ok("OK")
  finally:
    terminate(ghostunnel)
      
