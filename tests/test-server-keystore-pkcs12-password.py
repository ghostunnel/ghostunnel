#!/usr/bin/env python3

"""
Tests that ghostunnel can load a password-protected PKCS#12 keystore
via --keystore and --storepass flags.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
from subprocess import call, DEVNULL

ghostunnel = None
try:
    # create certs using standard helper (ECDSA P-256)
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # re-export server cert as password-protected PKCS#12
    call('openssl pkcs12 -export -out server_protected.p12 '
         '-in server.crt -inkey server.key -password pass:hunter2',
         shell=True, stderr=DEVNULL)

    # start ghostunnel with password-protected keystore
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server_protected.p12',
                                 '--storepass=hunter2',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # validate connection works
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_tunnel_ou("server", "ou=server")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
