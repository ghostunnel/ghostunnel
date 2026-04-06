#!/usr/bin/env python3

"""
Test that ensures that PKCS11 module support works.
"""

from common import LOCALHOST, STATUS_PORT, SocketPair, TcpClient, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, _ROOT_DIR
from shutil import copyfile
import os
import signal
import sys

ghostunnel = None
try:
    # Only run PKCS11 tests if requested
    if 'GHOSTUNNEL_TEST_PKCS11' not in os.environ:
        sys.exit(0)

    test_keys = os.path.join(_ROOT_DIR, 'test-keys')
    copyfile(os.path.join(test_keys, 'client-key.pem'), 'client.key')
    copyfile(os.path.join(test_keys, 'client-cert.pem'), 'client.crt')
    copyfile(os.path.join(test_keys, 'server-cert.pem'), 'server.crt')
    copyfile(os.path.join(test_keys, 'cacert.pem'), 'root.crt')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
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
    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # Test reloading
    ghostunnel.send_signal(signal.SIGUSR1)

    # Test some connections (again)
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
