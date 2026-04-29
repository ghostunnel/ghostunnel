#!/usr/bin/env python3

"""
Spins up a server and tests systemd socket activation on the listen socket.
"""

from common import (LOCALHOST, RootCert, STATUS_PORT, LISTEN_PORT, TARGET_PORT,
                    SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel,
                    require_platform, terminate)
from shutil import which
import sys

require_platform('Linux')

if not which('systemd-socket-activate'):
    print('no systemd-socket-activate binary found', file=sys.stderr)
    sys.exit(2)

ghostunnel = None
try:
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    ghostunnel = run_ghostunnel([
            'server',
            '--listen=systemd:server',
            '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
            '--keystore=server.p12',
            '--cacert=root.crt',
            '--allow-ou=client',
            '--status=systemd:status'],
            prefix=[
            'systemd-socket-activate',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--listen={0}:{1}'.format(LOCALHOST, STATUS_PORT),
            '--fdname=server:status',
            '--setenv=GOCOVERDIR',
            ])

    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_tunnel_ou("server", "ou=server")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
