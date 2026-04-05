#!/usr/bin/env python3

"""
Test that ensures that metrics bridge submission works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port, EXPECTED_SERVER_METRICS
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

        bridge_port = get_free_port(release=True)
        httpd = http.server.HTTPServer(
            ('localhost', bridge_port), FakeMetricsBridgeHandler)
        server = threading.Thread(target=httpd.handle_request)
        server.start()

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--enable-pprof',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--metrics-interval=1s',
                                     '--metrics-url=http://localhost:{0}/post'.format(bridge_port)])

        # wait for metrics to post
        for _ in range(10):
            if received_metrics:
                break
            else:
                # wait a little longer...
                time.sleep(1)

        if not received_metrics:
            raise Exception("did not receive metrics from instance")

        if not isinstance(received_metrics, list):
            raise Exception("ghostunnel metrics expected to be JSON list")

        metrics_found = [item['metric'] for item in received_metrics]
        missing_metrics = [metric for metric in EXPECTED_SERVER_METRICS if metric not in metrics_found]

        if missing_metrics:
            raise Exception('missing metrics from ghostunnel instance: %s' % missing_metrics)


        print_ok("OK")
    finally:
        terminate(ghostunnel)
