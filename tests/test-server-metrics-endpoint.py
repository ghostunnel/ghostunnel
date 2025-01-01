#!/usr/bin/env python3

"""
Test that ensures that metrics endpoint works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, print_ok, run_ghostunnel, terminate, urlopen
import urllib.request
import urllib.error
import urllib.parse
import time
import json

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--enable-pprof',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # Wait until ghostunnel is up
        TcpClient(STATUS_PORT).connect(20)

        # Load JSON metrics
        received_metrics1 = json.loads(str(urlopen(
            "https://{0}:{1}/_metrics?format=json".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

        received_metrics2 = json.loads(str(urlopen(
            "https://{0}:{1}/_metrics/json".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

        if not isinstance(received_metrics1, list):
            raise Exception("ghostunnel metrics expected to be JSON list")

        if not isinstance(received_metrics2, list):
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

        metrics_found = [item['metric'] for item in received_metrics1]
        missing_metrics = [metric for metric in expected_metrics if metric not in metrics_found]

        metrics_found = [item['metric'] for item in received_metrics2]
        missing_metrics = [metric for metric in expected_metrics if metric not in metrics_found]

        if missing_metrics:
            raise Exception('missing metrics from ghostunnel instance: %s' % missing_metrics)

        # Load Prometheus metrics
        metrics = str(urlopen(
            "https://{0}:{1}/_metrics?format=prometheus".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8')
        metrics = str(urlopen(
            "https://{0}:{1}/_metrics/prometheus".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8')

        print_ok("OK")
    finally:
        terminate(ghostunnel)
