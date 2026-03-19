#!/usr/bin/env python3

"""
Ensures that root certificates are reloaded as well.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, wait_for_status, LISTEN_PORT, TARGET_PORT
import signal
import os

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt',
                                     '--allow-ou=client'])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # Regenerate root certificates and reload
        RootCert.cleanup_certs(['root', 'client', 'server'])
        root.__init__('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        ghostunnel.send_signal(signal.SIGUSR1)
        wait_for_status(lambda info: True, timeout=10)
        
        # Make sure everything still works
        pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
