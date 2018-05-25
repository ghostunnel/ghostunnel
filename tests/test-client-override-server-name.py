#!/usr/bin/env python3

# Creates a ghostunnel. Ensures we can connect to a server signed by root1 but
# not root2.

from subprocess import Popen
from common import *
import socket
import ssl
import time
import os
import signal

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server1')
        root.create_signed_cert('client')
        root.create_signed_cert(
            'server2', san="IP:127.0.0.1,IP:::1,DNS:foobar")

        other_root = RootCert('other_root')
        other_root.create_signed_cert('other_server')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target=localhost:13002',
                                     '--keystore=client.p12',
                                     '--cacert=root.crt',
                                     '--timed-reload=1s',
                                     '--override-server-name=foobar',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect to server1, confirm that the tunnel is up
        pair = SocketPair(TcpClient(13001), TlsServer(
            'server2', 'root', 13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # connect to other_server, confirm that the tunnel isn't up
        try:
            pair = SocketPair(TcpClient(13001), TlsServer(
                'other_server', 'other_root', 13002))
            raise Exception('failed to reject other_server')
        except ssl.SSLError:
            print_ok("other_server correctly rejected")

        # connect to server2, confirm that the tunnel isn't up
        try:
            pair = SocketPair(TcpClient(13001), TlsServer(
                'server1', 'root', 13002))
            raise Exception('failed to reject server1')
        except ssl.SSLError:
            print_ok("server1 correctly rejected")

        # make sure also works after reload
        ghostunnel.send_signal(signal.SIGUSR1)
        TlsClient(None, 'root', STATUS_PORT).connect(20, 'client')
        print_ok("reload done")

        pair2 = SocketPair(TcpClient(13001), TlsServer(
            'server2', 'root', 13002))
        pair2.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair2.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair2.validate_closing_client_closes_server(
            "1: client closed -> server closed")
        pair2.cleanup()

        print_ok("OK")
    finally:
        terminate(ghostunnel)
