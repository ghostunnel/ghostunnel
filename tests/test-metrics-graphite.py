#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import urllib2, socket, ssl, time, os, signal, json, BaseHTTPServer, threading

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('new_server', 'root')
    create_signed_cert('client1', 'root')

    # Mock out a graphite server
    m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    m.settimeout(10)
    m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    m.bind((LOCALHOST, 13099))
    m.listen(1)

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1',
      '--status=localhost:13100', '--graphite=localhost:13099'])

    # Step 3: wait for metrics to be sent
    time.sleep(10)

    conn, addr = m.accept()
    for line in conn.makefile().readlines():
      if len(line.partition(' ')) != 3:
        raise Exception('invalid metric: ' + line)

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
    cleanup_certs(['root', 'server', 'new_server', 'client1'])
