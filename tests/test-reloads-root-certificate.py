#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that tunnel sees & reloads a root certificate
# change.

from subprocess import Popen, call
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import socket, ssl, time

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('client1', 'root')
    create_signed_cert('client2', 'root')

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1', '--allow-ou=client2', '--auto-reload'])

    # Step 3: create connections with client1 and client2
    pair1 = SocketPair('client1', 13001, 13000)
    pair1.validate_can_send_from_client("toto", "pair1 works")

    pair2 = SocketPair('client2', 13001, 13000)
    pair2.validate_can_send_from_client("toto", "pair2 works")

    # Step 4: re-new the server and client1 certs
    cleanup_certs(['root', 'server', 'client1'])
    print_ok("deleted root, server and client1")
    create_root_cert('root')
    print_ok("re-created root")
    create_signed_cert('server', 'root')
    print_ok("re-created server")
    create_signed_cert('client1', 'root')
    print_ok("re-created client1")

    # TODO: figure out a more reliable way to tell that the tunnel picked up
    # the new cert.
    time.sleep(30)

    # Step 5: ensure that client1 can connect
    try:
      pair3 = SocketPair('client1', 13001, 13000)
      pair3.validate_can_send_from_client("toto", "pair3 works")
    except ssl.SSLError:
      # FIXME: retrying to due flakiness, which for some reason only
      # seems to appear on travis-ci :(
      pair3 = SocketPair('client1', 13001, 13000)
      pair3.validate_can_send_from_client("toto", "pair3 works")

    # Step 6: ensure that client2 cannot connect
    try:
      pair4 = SocketPair('client2', 13001, 13000)
      raise Exception('client2 was able to connect')
    except ssl.SSLError:
      print_ok("client2 failed to connect")

    # Step 7: ensure that pair1 and pair2 are still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")
    pair2.validate_can_send_from_client("toto", "pair2 still works")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
    cleanup_certs(['root', 'server', 'client1', 'client2'])
