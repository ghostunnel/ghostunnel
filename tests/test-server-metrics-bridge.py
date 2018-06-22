#!/usr/bin/env python3

"""
Test that ensures that metrics bridge submission works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate
import time
import json
import http.server
import threading

received_metrics = None


class FakeMetricsBridgeHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        # pylint: disable=global-statement
        global received_metrics
        print_ok("handling POST to fake bridge")
        length = int(self.headers['Content-Length'])
        received_metrics = json.loads(self.rfile.read(length).decode('utf-8'))


if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        httpd = http.server.HTTPServer(
            ('localhost', 13080), FakeMetricsBridgeHandler)
        server = threading.Thread(target=httpd.handle_request)
        server.start()

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--enable-pprof',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--metrics-interval=1s',
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

        if not isinstance(received_metrics, list):
            raise Exception("ghostunnel metrics expected to be JSON list")

        # some metrics we expect to be present
        expected_metrics = [
            "ghostunnel.accept.total",
            "ghostunnel.accept.success",
            "ghostunnel.accept.timeout",
            "ghostunnel.accept.error",
            "ghostunnel.conn.open",
            "ghostunnel.conn.lifetime.count",
            "ghostunnel.conn.lifetime.min",
            "ghostunnel.conn.lifetime.max",
            "ghostunnel.conn.lifetime.mean",
            "ghostunnel.conn.lifetime.50-percentile",
            "ghostunnel.conn.lifetime.75-percentile",
            "ghostunnel.conn.lifetime.95-percentile",
            "ghostunnel.conn.lifetime.99-percentile",
            "ghostunnel.conn.handshake.count",
            "ghostunnel.conn.handshake.min",
            "ghostunnel.conn.handshake.max",
            "ghostunnel.conn.handshake.mean",
            "ghostunnel.conn.handshake.50-percentile",
            "ghostunnel.conn.handshake.75-percentile",
            "ghostunnel.conn.handshake.95-percentile",
            "ghostunnel.conn.handshake.99-percentile",
        ]

        metrics_found = [item['metric'] for item in received_metrics]
        missing_metrics = [metric for metric in expected_metrics if metric not in metrics_found]

        if missing_metrics:
            raise Exception('missing metrics from ghostunnel instance: %s' % missing_metrics)


        print_ok("OK")
    finally:
        terminate(ghostunnel)
