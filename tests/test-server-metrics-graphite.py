#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import RootCert, LOCALHOST, SocketPair, print_ok
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, http.server, threading

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')

    # Mock out a graphite server
    m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    m.settimeout(10)
    m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    m.bind((LOCALHOST, 13099))
    m.listen(1)

    # start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status=localhost:13100', '--graphite=localhost:13099'])

    # wait for metrics to be sent
    conn, addr = m.accept()
    for line in conn.makefile().readlines():
      if len(line.partition(' ')) != 3:
        raise Exception('invalid metric: ' + line)

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
