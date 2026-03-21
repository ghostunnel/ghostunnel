#!/usr/bin/env python3

"""
Ensures that client gets a timeout if there is no server.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port
import socket

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

        # client should fail to connect since nothing is listening on wrong_port
        wrong_port = get_free_port()
        try:
            pair = SocketPair(
                TlsClient('client', 'root', LISTEN_PORT), TcpServer(wrong_port))
            raise Exception('client should have failed to connect')
        except socket.timeout:
            print_ok("timeout when nothing is listening on {0}".format(wrong_port))

        # client should connect
        pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.cleanup()
        print_ok("OK")
    finally:
        terminate(ghostunnel)
