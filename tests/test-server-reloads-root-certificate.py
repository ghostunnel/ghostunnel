#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that tunnel sees & reloads a root certificate
# change.

from subprocess import Popen, call
from test_common import RootCert, LOCALHOST, SocketPair, print_ok, wait_for_cert
import socket, ssl, time, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client1')
    root.create_signed_cert('client2')

    # start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client1', '--allow-ou=client2',
      '--status={0}:13100'.format(LOCALHOST)])

    # create connections with client1 and client2
    pair1 = SocketPair('client1', 13001, 13000)
    pair1.validate_can_send_from_client("toto", "pair1 works")

    pair2 = SocketPair('client2', 13001, 13000)
    pair2.validate_can_send_from_client("toto", "pair2 works")

    # re-new the server and client1 certs
    # TODO: use os.rename instead.
    RootCert.cleanup_certs(['root', 'server', 'client1'])
    print_ok("deleted root, server and client1")
    root2 = RootCert('root')
    print_ok("re-created root")
    root2.create_signed_cert('server')
    print_ok("re-created server")
    root2.create_signed_cert('client1')
    print_ok("re-created client1")

    # Trigger reload
    ghostunnel.send_signal(signal.SIGUSR1)
    wait_for_cert(13100, 'server.crt')

    # ensure that client1 can connect
    try:
      pair3 = SocketPair('client1', 13001, 13000)
      pair3.validate_can_send_from_client("toto", "pair3 works")
    except ssl.SSLError:
      # FIXME: retrying to due flakiness, which for some reason only
      # seems to appear on travis-ci :(
      pair3 = SocketPair('client1', 13001, 13000)
      pair3.validate_can_send_from_client("toto", "pair3 works")

    # ensure that client2 cannot connect
    try:
      pair4 = SocketPair('client2', 13001, 13000)
      raise Exception('client2 was able to connect')
    except ssl.SSLError:
      print_ok("client2 failed to connect")

    # ensure that pair1 and pair2 are still alive
    pair1.validate_can_send_from_client("toto", "pair1 still works")
    pair2.validate_can_send_from_client("toto", "pair2 still works")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
