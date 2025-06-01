#!/usr/bin/env python3

"""
Tests that ghostunnel respects the max-tls-version flag by verifying that:
1. TLS 1.2 connections are accepted when max version is set to TLS1.2
2. TLS 1.3 connections are rejected when max version is set to TLS1.2
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TlsClient, TcpServer, print_ok, run_ghostunnel, terminate
import ssl
import time

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel with max TLS version set to 1.2
        ghostunnel = run_ghostunnel(['server',
                                   '--listen={0}:13001'.format(LOCALHOST),
                                   '--target={0}:13002'.format(LOCALHOST),
                                   '--keystore=server.p12',
                                   '--cacert=root.crt',
                                   '--allow-ou=client',
                                   '--max-tls-version=TLS1.2',
                                   '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

        # Wait for startup
        TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

        # Create backend socket
        backend = TcpServer(13002)
        backend.listen()

        # Test TLS 1.2 client (should succeed)
        print_ok("testing TLS 1.2 connection (should succeed)...")
        client = TlsClient('client', 'root', 13001,
                         min_version=ssl.TLSVersion.TLSv1_2,
                         max_version=ssl.TLSVersion.TLSv1_2)
        client.connect()
        client.get_socket().send(b'hello')
        client.cleanup()
        print_ok("successfully connected using TLS 1.2")

        # Test TLS 1.3 client (should fail)
        print_ok("testing TLS 1.3 connection (should fail)...")
        client = TlsClient('client', 'root', 13001,
                         min_version=ssl.TLSVersion.TLSv1_3,
                         max_version=ssl.TLSVersion.TLSv1_3)
        
        failed = False
        try:
            client.connect()
        except Exception as e:
            failed = True
        if not failed:
            raise Exception("expected TLS 1.3 connection to fail, but it succeeded")
        print_ok("TLS 1.3 connection failed as expected")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
        if 'backend' in locals():
            backend.cleanup() 