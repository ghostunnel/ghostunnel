#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs, wait_for_status
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('new_server', 'root')
    create_signed_cert('client1', 'root')

    # Step 2: start ghostunnel, set min TLS version to v1.2
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1',
      '--status={0}:13100'.format(LOCALHOST), '--min-tls=1.2'])
    wait_for_status(13100)

    # Step 3: try to connect with TLS < 1.2
    urllib.request.urlopen('https://{0}:13100/_status'.format(LOCALHOST), context=ssl.SSLContext(ssl.PROTOCOL_SSLv23 & ssl.OP_NO_TLSv1_2))

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
    cleanup_certs(['root', 'server', 'new_server', 'client1'])
