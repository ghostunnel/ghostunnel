#!/usr/bin/env python3

"""
Ensures metrics are collected and pushed when a push sink is the ONLY sink:
--metrics-graphite without --status. This exercises the branch where the
metrics gate enables collection solely because of a push reporter (with no
pull surface configured at all).
"""

from common import LOCALHOST, RootCert, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port
import socket

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')

    # Mock out a graphite server
    graphite_port = get_free_port(release=True)
    m = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    m.settimeout(10)
    m.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    m.bind((LOCALHOST, graphite_port))
    m.listen(1)

    # start ghostunnel with graphite as the only metrics sink (no --status)
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--metrics-interval=1s',
                                 '--metrics-graphite=localhost:{0}'.format(graphite_port)])

    # wait for metrics to be sent
    conn, addr = m.accept()
    lines = conn.makefile().readlines()
    if not lines:
        raise Exception('no metrics received on graphite socket')
    for line in lines:
        parts = line.split()
        if len(parts) != 3:
            raise Exception('invalid metric line: ' + repr(line))
        float(parts[1])  # value must be numeric
        int(parts[2])    # timestamp must be an integer
    names = set(line.split()[0] for line in lines)
    for expected in ['ghostunnel.accept.total.count',
                     'ghostunnel.runtime.goroutines.value']:
        if expected not in names:
            raise Exception(
                'expected metric {0} missing from graphite report'.format(expected))

    print_ok("OK")
finally:
    terminate(ghostunnel)
