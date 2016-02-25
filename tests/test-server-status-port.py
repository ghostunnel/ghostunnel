#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, SocketPair, print_ok, wait_for_status, wait_for_cert
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('new_server')

    # start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status={0}:13100'.format(LOCALHOST)])
    wait_for_status(13100)

    urlopen = lambda path: urllib.request.urlopen(path, cafile='root.crt')

    # read status information
    status = json.loads(str(urlopen("https://{0}:13100/_status".format(LOCALHOST)).read(), 'utf-8'))
    metrics = json.loads(str(urlopen("https://{0}:13100/_metrics".format(LOCALHOST)).read(), 'utf-8'))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    if type(metrics) != list:
        raise Exception("ghostunnel metrics expected to be JSON list")

    # reload
    os.rename('new_server.p12', 'server.p12')
    ghostunnel.send_signal(signal.SIGUSR1)
    wait_for_cert(13100, 'new_server.crt')

    # read status information
    status = json.loads(str(urlopen("https://{0}:13100/_status".format(LOCALHOST)).read(), 'utf-8'))
    metrics = json.loads(str(urlopen("https://{0}:13100/_metrics".format(LOCALHOST)).read(), 'utf-8'))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    if type(metrics) != list:
        raise Exception("ghostunnel metrics expected to be JSON list")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
