#!/usr/bin/env python3

"""
Test that ensures that Graphite metrics submission works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port
import socket

if __name__ == "__main__":
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

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--metrics-interval=1s',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--metrics-graphite=localhost:{0}'.format(graphite_port)])

        # wait for metrics to be sent
        conn, addr = m.accept()
        for line in conn.makefile().readlines():
            if len(line.partition(' ')) != 3:
                raise Exception('invalid metric: ' + line)

        print_ok("OK")
    finally:
        terminate(ghostunnel)
