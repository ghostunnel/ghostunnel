#!/usr/bin/env python3

"""
Ensures that tunnel sees & reloads a certificate change.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
import os

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('new_server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--timed-reload=1s',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # create connections with client
        pair1 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.validate_tunnel_ou("server", "pair1 -> ou=server")

        # Replace keystore and trigger reload
        os.rename('new_server.p12', 'server.p12')
        # NOT reloading explicitly here (should be automatic)

        TlsClient(None, 'root', STATUS_PORT).connect(20, 'new_server')
        print_ok("reload done")

        # create connections with client
        pair2 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair2.validate_can_send_from_client("toto", "pair2 works")
        pair2.validate_tunnel_ou("new_server", "pair2 -> ou=new_server")
        pair2.cleanup()

        # ensure that pair1 is still alive
        pair1.validate_can_send_from_client("toto", "pair1 still works")
        pair1.cleanup()

        print_ok("OK")
    finally:
        terminate(ghostunnel)
