#!/usr/bin/env python3

"""
Spins up a client and tests systemd socket activation.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate
from shutil import which
import sys

if __name__ == "__main__":
    ghostunnel = None

    if not which('systemd-socket-activate'):
        print_ok('skipping systemd socket activation test, no systemd-socket-activate binary found')
        sys.exit(0)

    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel([
                'client',
                '--listen=systemd:client',
                '--target={0}:{1}'.format(LOCALHOST, STATUS_PORT),
                '--keystore=client.p12',
                '--status=systemd:status',
                '--cacert=root.crt'],
                prefix=[
                'systemd-socket-activate',
                '--listen={0}:13001'.format(LOCALHOST),
                '--listen={0}:{1}'.format(LOCALHOST, STATUS_PORT),
                '--fdname=client:status',
                '--setenv=GHOSTUNNEL_INTEGRATION_TEST',
                '--setenv=GHOSTUNNEL_INTEGRATION_ARGS',
                ])

        # Connect on status port to trigger socket activation
        # so it will spin up the ghostunnel instance
        TcpClient(STATUS_PORT).connect(20)

        print_ok("OK")
    finally:
        terminate(ghostunnel)
