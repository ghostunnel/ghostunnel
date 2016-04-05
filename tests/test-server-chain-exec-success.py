#!/usr/bin/env python3

# Creates a ghostunnel with a subprocess (netcat), connects, and waits for termination.

from subprocess import Popen
from test_common import *
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel server with nc as child
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--', 'nc', '-l', LOCALHOST, '13002'])

    # should terminate by itself (since child terminates)
    for i in range(0, 20):
      try:
        # connect once (nc terminates after one connection)
        TlsClient('client', 'root', 13001).connect(20)
        ghostunnel.wait(timeout=1)
      except:
        pass
      if ghostunnel.returncode != None:
        if ghostunnel.returncode == 0:
          print_ok("exited normally")
          sys.exit(0)
        else:
          raise Exception("got non-zero error code, even though child exited normally?")
      time.sleep(1)

    raise Exception("did not terminate, though it should have")
  finally:
    terminate(ghostunnel)
