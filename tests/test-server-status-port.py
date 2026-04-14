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

    print_ok("OK")
finally:
    terminate(ghostunnel)
