#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that --min-tls flag works.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, STATUS_PORT, SocketPair, print_ok, TlsClient, TcpServer
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel, set min TLS version to v1.2
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT), '--min-tls=1.2'])
    pair = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))

    # try to connect with TLS < 1.2
    urllib.request.urlopen('https://{0}:{1}/_status'.format(LOCALHOST, STATUS_PORT), context=ssl.SSLContext(ssl.PROTOCOL_SSLv23 & ssl.OP_NO_TLSv1_2))

    # should fail with value error, because we set min TLS version to v1.2
    # but we tried to connect with TLS < 1.2. if we didn't get an exception,
    # we managed to connect with a lesser version which is not the expected behavior
    raise Exception('urlopen with TLSv1.1 should fail if --min-tls=1.2 was set')

  except ValueError as e:
    if str(e) != 'invalid protocol version':
      raise Exception('unexpected error: ' + str(e) + ' (should be "invalid protocol version")')
    print_ok('correctly failed to connect with TLSv1.1 if --min-tls=1.2 was set')
  finally:
    if ghostunnel:
      ghostunnel.kill()
