#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that client gets a timeout if there is no
# server.

from subprocess import Popen
from common import *
import socket
import ssl

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(
                                         LOCALHOST), '--keystore=server.p12',
                                     '--status={0}:{1}'.format(
                                         LOCALHOST, STATUS_PORT),
                                     '--cacert=root.crt', '--allow-ou=client'])

        # client should fail to connect since nothing is listening on 13003
        try:
            pair = SocketPair(
                TlsClient('client', 'root', 13001), TcpServer(13003))
            raise Exception('client should have failed to connect')
        except socket.timeout:
            print_ok("timeout when nothing is listening on 13003")

        # client should connect
        pair = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))
        pair.cleanup()
        print_ok("OK")
    finally:
        terminate(ghostunnel)
