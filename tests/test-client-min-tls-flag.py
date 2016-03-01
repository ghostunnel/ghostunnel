#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that --min-tls flag works.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, STATUS_PORT, SocketPair, print_ok, TcpClient, TlsServer, TlsClient
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel, set min TLS version to v1.2
    ghostunnel = Popen(['../ghostunnel', 'client', '--listen={0}:13004'.format(LOCALHOST),
      '--target={0}:13005'.format(LOCALHOST), '--keystore=client.p12',
      '--cacert=root.crt', '--min-tls=1.2',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    try:
      # setup a server which talks TLS < 1.2
      pair = SocketPair(TcpClient(13004), TlsServer('client', 'root', 13005, ssl_version=ssl.PROTOCOL_SSLv3))

      # should fail with value error, because we set min TLS version to v1.2
      # but we tried to connect with TLS < 1.2. if we didn't get an exception,
      # we managed to connect with a lesser version which is not the expected behavior
      raise Exception('urlopen with TLSv1.1 should fail if --min-tls=1.2 was set')

    except ssl.SSLError as e:
      print(e)
      if str(e).find("[SSL: WRONG_VERSION_NUMBER]") == -1:
        raise Exception('unexpected error: ' + str(e) + ' (should be "[SSL: WRONG_VERSION_NUMBER]')
      print_ok('correctly failed to connect with SSLv3 if --min-tls=1.2 was set')

    try:
      # check STATUS_PORT
      TlsClient('client', 'root', STATUS_PORT, ssl_version=ssl.PROTOCOL_SSLv3).connect()
    except ssl.SSLError as e:
      print(e)
      if str(e).find("[SSL: WRONG_VERSION_NUMBER]") == -1:
        raise Exception('unexpected error: ' + str(e) + ' (should be "[SSL: WRONG_VERSION_NUMBER]')
      print_ok('correctly failed to connect with SSLv3 if --min-tls=1.2 was set')
  finally:
    if ghostunnel:
      ghostunnel.kill()
