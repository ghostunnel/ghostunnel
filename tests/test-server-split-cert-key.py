#!/usr/bin/env python3

"""
Test that ensures that we can use the --cert/--key flags.
"""

from common import LOCALHOST, STATUS_PORT, TcpClient, print_ok, run_ghostunnel, terminate, RootCert, SocketPair, TlsClient, TcpServer
import urllib.request
import urllib.error
import urllib.parse
import os
import signal
import json
import sys

if __name__ == "__main__":
    ghostunnel = None
    try:
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--cert=server.crt',
                                     '--key=server.key',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--allow-ou=client'])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(
            TlsClient('client', 'root', 13001), TcpServer(13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
