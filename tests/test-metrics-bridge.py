#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that /_status endpoint works.

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import urllib2, socket, ssl, time, os, signal, json, BaseHTTPServer, threading

received_metrics = None

class FakeMetricsBridgeHandler(BaseHTTPServer.BaseHTTPRequestHandler):
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

    httpd = BaseHTTPServer.HTTPServer(('localhost',13080), FakeMetricsBridgeHandler)
    server = threading.Thread(target=httpd.handle_request)
    server.start()

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13100'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1',
      '--status-port=13100', '--metrics-bridge=http://localhost:13080/post'])

    # Step 3: wait for metrics to post
    time.sleep(5)

    if received_metrics:
      if type(received_metrics) != list:
        raise Exception("ghostunnel metrics expected to be JSON list")
    else:
      raise Exception("did not receive metrics from instance")

    print_ok("OK")
  finally:
    if ghostunnel:
      ghostunnel.kill()
    cleanup_certs(['root', 'server', 'new_server', 'client1'])
