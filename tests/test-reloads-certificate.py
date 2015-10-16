#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that tunnel sees & reloads a certificate change.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('new_server', 'root')
    create_signed_cert('client1', 'root')

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])

    # Step 3: create connections with client1
    pair1 = SocketPair('client1', 13001, 13000)
    pair1.validate_can_send_from_client("toto", "pair1 works")
    pair1.validate_tunnel_ou("server", "pair1 -> ou=server")

    # Replace keystore and trigger reload
    os.rename('new_server.p12', 'server.p12')
    ghostunnel.send_signal(signal.SIGUSR1)
    time.sleep(10)

    # Step 4: create connections with client1
    pair2 = SocketPair('client1', 13001, 13000)
    pair2.validate_can_send_from_client("toto", "pair2 works")
    pair2.validate_tunnel_ou("new_server", "pair2 -> ou=new_server")

    # Step 5: ensure that pair1 is still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
    cleanup_certs(['root', 'server', 'new_server', 'client1'])
