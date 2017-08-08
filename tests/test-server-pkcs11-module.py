#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen, PIPE
from common import *
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Only run PKCS11 tests if requested
    if 'GHOSTUNNEL_TEST_PKCS11' not in os.environ:
      sys.exit(0)

    # start ghostunnel
    # hack: point target to STATUS_PORT so that /_status doesn't 503.
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:{1}'.format(LOCALHOST, STATUS_PORT), '--keystore=../test-keys/server.crt',
      '--pkcs11-module={0}'.format(os.environ['PKCS11_MODULE']),
      '--pkcs11-token-label={0}'.format(os.environ['PKCS11_LABEL']),
      '--pkcs11-pin={0}'.format(os.environ['PKCS11_PIN']),
      '--cacert=../test-keys/root.crt', '--allow-ou=client',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    urlopen = lambda path: urllib.request.urlopen(path, cafile='../test-keys/root.crt')

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(3)
    status = json.loads(str(urlopen("https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
    metrics = json.loads(str(urlopen("https://{0}:{1}/_metrics".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    if type(metrics) != list:
        raise Exception("ghostunnel metrics expected to be JSON list")

    # Test reloading
    ghostunnel.send_signal(signal.SIGUSR1)

    status = json.loads(str(urlopen("https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    print_ok("OK")
  finally:
    terminate(ghostunnel)
      
