#!/usr/bin/env python3

"""
Ensures that client mode can tunnel through an HTTPS CONNECT proxy that does
not ask for a client certificate, with no --proxy-* flags at all. The proxy
is verified against --cacert.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, FakeConnectProxy

ghostunnel = None
proxy = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')
    root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')

    proxy = FakeConnectProxy(certfile='proxy.crt', keyfile='proxy.key')

    # start ghostunnel with an https proxy but no proxy credential
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--proxy=' + proxy.url(),
                                 '--connect-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # connect to server, confirm that the tunnel is up
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client('hello world', 'client -> server')
    pair.validate_can_send_from_server('hello world', 'server -> client')
    pair.validate_closing_client_closes_server('closing client')
    pair.cleanup()

    # the proxy must have seen the connection, without a client certificate
    proxy.assert_client_sequence(None)
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if proxy:
        proxy.shutdown()
