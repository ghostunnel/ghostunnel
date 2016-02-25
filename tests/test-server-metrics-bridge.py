#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs, wait_for_status
import urllib.request, urllib.error, urllib.parse, socket, ssl, time, os, signal, json, http.server, threading

received_metrics = None

class FakeMetricsBridgeHandler(http.server.BaseHTTPRequestHandler):
  def do_POST(self):
    global received_metrics
    print_ok("handling POST to fake bridge")
    length = int(self.headers['Content-Length'])
    received_metrics = json.loads(self.rfile.read(length).decode('utf-8'))

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('new_server', 'root')
    create_signed_cert('client1', 'root')

    httpd = http.server.HTTPServer(('localhost',13080), FakeMetricsBridgeHandler)
    server = threading.Thread(target=httpd.handle_request)
    server.start()

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1',
      '--status={0}:13100'.format(LOCALHOST), '--metrics-url=http://localhost:13080/post'])

    # Step 3: wait for metrics to post
    for i in range(0, 10):
      if received_metrics:
        break
      else:
        # wait a little longer...
        time.sleep(1)

    if not received_metrics:
      raise Exception("did not receive metrics from instance")

    if type(received_metrics) != list:
      raise Exception("ghostunnel metrics expected to be JSON list")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
    cleanup_certs(['root', 'server', 'new_server', 'client1'])
