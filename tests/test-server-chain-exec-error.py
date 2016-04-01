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

    # start ghostunnel server with false as child
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--', 'false'])

    # should terminate by itself (since child terminates)
    for i in range(0, 10):
      try:
        ghostunnel.wait(timeout=1)
      except:
        pass
      if ghostunnel.returncode != None:
        if ghostunnel.returncode == 0:
          raise Exception("got error code 0, even though child exited with non-zero")
        else:
          print_ok("non-zero error code if child has non-zero error code")
          break
      time.sleep(1)

    print_ok("OK")
  finally:
    terminate(ghostunnel)
