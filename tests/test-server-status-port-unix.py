#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint using UNIX sockets works.

from subprocess import Popen
from common import *
from tempfile import mkdtemp
from shutil import rmtree
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, sys, http.client

class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__(self, 'localhost')
        self.host = 'localhost'
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')

    # start ghostunnel
    tempdir = mkdtemp()
    path = os.path.join(tempdir, 'ghostunnel-status-socket')

    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target=unix:{0}'.format(path), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client',
      '--status=unix:{0}'.format(path)])

    # wait for startup
    for i in range(0, 10):
      if os.path.exists(path):
        break
      time.sleep(1)

    # read status information
    conn = UnixHTTPConnection(path)
    conn.connect()

    conn.request('GET', '/_status')
    status = json.loads(str(conn.getresponse().read(), encoding="UTF-8"))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    print_ok("OK")
  finally:
    terminate(ghostunnel)
    rmtree(tempdir)
      
