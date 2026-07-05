#!/usr/bin/env python3

"""
Ensures that /_status endpoint works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, TlsClient, print_ok, reload_args, run_ghostunnel, terminate, trigger_reload, urlopen, LISTEN_PORT
import os
import json

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('new_server')
    root.create_signed_cert('client')

    # start ghostunnel
    # hack: point target to STATUS_PORT so that /_status doesn't 503.
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args())

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(20)
    status = json.loads(str(urlopen(
        "https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
    metrics = json.loads(str(urlopen(
        "https://{0}:{1}/_metrics".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    if not isinstance(metrics, list):
        raise Exception("ghostunnel metrics expected to be JSON list")

    # The metric names are part of Ghostunnel's exported contract; assert that
    # representative counter, gauge-like, and expanded-timer names are present.
    def metric_names(entries):
        return {entry['metric'] for entry in entries}

    def assert_metrics_present(entries):
        names = metric_names(entries)
        for expected in ['ghostunnel.conn.open', 'ghostunnel.accept.total',
                         'ghostunnel.conn.handshake.count',
                         'ghostunnel.conn.handshake.99-percentile']:
            if expected not in names:
                raise Exception(
                    "expected metric {0} missing from /_metrics".format(expected))
        # Deprecated/removed timer fields must not reappear in JSON.
        for banned_suffix in ['.std-dev', '.std_dev', '.variance', '.999-percentile',
                              '.count_ps', '.mean-rate', '.rate1']:
            for name in names:
                if name.endswith(banned_suffix):
                    raise Exception(
                        "unexpected deprecated metric {0} present".format(name))

    assert_metrics_present(metrics)

    # Prometheus endpoint should expose the native summary and standard collectors.
    prometheus = str(urlopen(
        "https://{0}:{1}/_metrics/prometheus".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8')
    for expected in ['ghostunnel_conn_open', 'ghostunnel_conn_handshake', 'go_goroutines']:
        if expected not in prometheus:
            raise Exception(
                "expected prometheus metric {0} missing".format(expected))
    for banned in ['_std_dev', '_variance', '_timer_bucket', '_rate1']:
        if banned in prometheus:
            raise Exception(
                "unexpected deprecated prometheus metric containing {0}".format(banned))

    # reload, check we get the new cert on /_status
    os.replace('new_server.p12', 'server.p12')
    trigger_reload(ghostunnel)
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'new_server')
    print_ok('/_status seems up')

    # read status information
    status = json.loads(str(urlopen(
        "https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
    metrics = json.loads(str(urlopen(
        "https://{0}:{1}/_metrics".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    if not status['ok']:
        raise Exception("ghostunnel reported non-ok status")

    if not isinstance(metrics, list):
        raise Exception("ghostunnel metrics expected to be JSON list")

    assert_metrics_present(metrics)

    print_ok("OK")
finally:
    terminate(ghostunnel)
