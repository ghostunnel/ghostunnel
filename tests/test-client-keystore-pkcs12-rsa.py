#!/usr/bin/env python3

"""
Tests that ghostunnel client mode works with a PKCS#12 keystore
containing an RSA private key for client authentication.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT

ghostunnel = None
try:
    root = RootCert('root', algorithm='rsa')
    root.create_signed_cert('server', p12_password=None)
    root.create_signed_cert('client', p12_password='testpass')

    # start ghostunnel in client mode with RSA PKCS#12 keystore
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--storepass=testpass',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # validate connection through the tunnel
    pair = SocketPair(
        TcpClient(LISTEN_PORT),
        TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_client_cert("client", "client cert -> ou=client")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
