#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import *
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
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    httpd = http.server.HTTPServer(('localhost',13080), FakeMetricsBridgeHandler)
    server = threading.Thread(target=httpd.handle_request)
    server.start()

    # start ghostunnel
    ghostunnel = run_ghostunnel(['client', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=client.p12',
      '--cacert=root.crt', '--metrics-interval=1s',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--metrics-url=http://localhost:13080/post'])

    # wait for metrics to post
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
    terminate(ghostunnel)
      
