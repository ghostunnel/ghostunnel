#!/usr/bin/env python3

"""
Spins up a client and tests systemd socket activation.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate
from distutils.spawn import find_executable
import sys

if __name__ == "__main__":
    ghostunnel = None

    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel([
                'client',
                '--listen=launchd:client',
                '--target={0}:{1}'.format(LOCALHOST, STATUS_PORT),
                '--keystore=client.p12',
                '--status=systemd:status',
                '--cacert=root.crt'])

        ghostunnel.wait(timeout=10)
        if ghostunnel.returncode == 0:
            raise Exception('Should fail on invalid socket')

        print_ok("OK")
    finally:
        terminate(ghostunnel)
