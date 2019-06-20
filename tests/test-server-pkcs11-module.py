#!/usr/bin/env python3

"""
Test that ensures that PKCS11 module support works.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, UnixServer, TcpClient, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate
from shutil import copyfile
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
        # Only run PKCS11 tests if requested
        if 'GHOSTUNNEL_TEST_PKCS11' not in os.environ:
            sys.exit(0)

        copyfile('../test-keys/client-key.pem', 'client.key')
        copyfile('../test-keys/client-cert.pem', 'client.crt')
        copyfile('../test-keys/server-cert.pem', 'server.crt')
        copyfile('../test-keys/cacert.pem', 'root.crt')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--cert=server.crt',
                                     '--pkcs11-module={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_MODULE']),
                                     '--pkcs11-token-label={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_LABEL']),
                                     '--pkcs11-pin={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_PIN']),
                                     '--cacert=root.crt',
                                     '--allow-cn=client',
                                     '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

        # block until ghostunnel is up
        TcpClient(STATUS_PORT).connect(3)

        # Test some connections
        pair = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # Test reloading
        ghostunnel.send_signal(signal.SIGUSR1)

        # Test some connections (again)
        pair = SocketPair(TlsClient('client', 'root', 13001), TcpServer(13002))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
