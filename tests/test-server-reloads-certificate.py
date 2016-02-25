#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that tunnel sees & reloads a certificate change.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, SocketPair, print_ok, wait_for_cert
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
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status={0}:13100'.format(LOCALHOST)])

    # create connections with client
    pair1 = SocketPair('client', 13001, 13000)
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_tunnel_ou("server", "pair1 -> ou=server")

    # Replace keystore and trigger reload
    os.rename('new_server.p12', 'server.p12')
    ghostunnel.send_signal(signal.SIGUSR1)
    wait_for_cert(13100, 'new_server.crt')

    # create connections with client
    pair2 = SocketPair('client', 13001, 13000)
    pair2.validate_can_send_from_client("toto", "pair2 works")
    pair2.validate_tunnel_ou("new_server", "pair2 -> ou=new_server")

    # ensure that pair1 is still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
