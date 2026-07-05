#!/usr/bin/env python3

"""
Ensures a failing --metrics-url receiver does not break the instance: the
push loop must keep trying after a rejected report (non-2xx) and the tunnel
must keep proxying connections throughout.
"""

from common import LOCALHOST, RootCert, SocketPair, TcpServer, TlsClient, \
    print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, STATUS_PORT, \
    get_free_port
import time
import http.server
import threading

received_posts = 0


class FailingMetricsHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # pylint: disable=global-statement
        global received_posts
        received_posts += 1
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        self.send_error(500, 'rejected on purpose')

    def log_message(self, *args):
        pass


ghostunnel = None
httpd = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # metrics receiver that rejects every POST
    receiver_port = get_free_port(release=True)
    httpd = http.server.HTTPServer(('localhost', receiver_port), FailingMetricsHandler)
    server = threading.Thread(target=httpd.serve_forever, daemon=True)
    server.start()

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--metrics-interval=1s',
                                 # --status is needed by SocketPair, which waits
                                 # on the status port before connecting
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
                                 '--metrics-url=http://localhost:{0}/post'.format(receiver_port)])

    # wait for at least two rejected POSTs: the second one proves the loop
    # survived the first failure instead of dying with it
    for _ in range(30):
        if received_posts >= 2:
            break
        time.sleep(1)
    if received_posts < 2:
        raise Exception(
            'expected the push loop to keep POSTing after a 500, got {0} POSTs'.format(received_posts))

    # the tunnel must still proxy connections while reports are rejected
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("toto", "tunnel works despite failing metrics receiver")
    pair.cleanup()

    if ghostunnel.poll() is not None:
        raise Exception('ghostunnel must not exit because a metrics receiver fails')

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if httpd:
        httpd.shutdown()
