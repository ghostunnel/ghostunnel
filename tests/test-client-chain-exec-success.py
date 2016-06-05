#!/usr/bin/env python3

# Creates a ghostunnel with a subprocess (netcat), connects, and waits for termination.

from subprocess import Popen
from common import *
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # start ghostunnel server with false as child
    ghostunnel = run_ghostunnel(['client', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=client.p12',
      '--cacert=root.crt', '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--', 'true'])

    # should terminate by itself (since child terminates)
    for i in range(0, 10):
      try:
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

    print_ok("OK")
  finally:
    terminate(ghostunnel)
