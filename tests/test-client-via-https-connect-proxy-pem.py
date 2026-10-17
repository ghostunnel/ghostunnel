#!/usr/bin/env python3

"""
Ensures that client mode can authenticate to an HTTPS CONNECT proxy with a
client certificate given as separate --proxy-cert/--proxy-key PEM files, and
that a replaced proxy credential is picked up on reload.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, reload_args, reload_and_wait, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, FakeConnectProxy
import os

ghostunnel = None
proxy = None
try:
    # create certs. The proxy and its clients use a separate PKI from the
    # tunnel target, so that --proxy-cacert is exercised independently of
    # --cacert.
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')

    proxy_root = RootCert('proxy_root')
    proxy_root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')
    proxy_root.create_signed_cert('proxy_client', p12_password=None)
    proxy_root.create_signed_cert('new_proxy_client', p12_password=None)

    proxy = FakeConnectProxy(certfile='proxy.crt', keyfile='proxy.key',
                             cafile='proxy_root.crt', require_client_cert=True)

    # start ghostunnel with separate --proxy-cert and --proxy-key
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--proxy=' + proxy.url(),
                                 '--proxy-cert=proxy_client.crt',
                                 '--proxy-key=proxy_client.key',
                                 '--proxy-cacert=proxy_root.crt',
                                 '--connect-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]
                                + reload_args())

    # connect to server, confirm that the tunnel is up
    pair1 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair1.validate_can_send_from_client('hello world 1', '1: client -> server')
    pair1.validate_can_send_from_server('hello world 1', '1: server -> client')
    pair1.validate_closing_client_closes_server('closing client 1')
    pair1.cleanup()

    proxy.assert_client_sequence('proxy_client')
    print_ok("first connection verified with proxy_client cert/key PEM")

    # replace proxy_client.crt and proxy_client.key with new_proxy_client
    # and reload; new connections must present the new certificate
    os.replace('new_proxy_client.crt', 'proxy_client.crt')
    os.replace('new_proxy_client.key', 'proxy_client.key')
    reload_and_wait(ghostunnel, timeout=30)

    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair2.validate_can_send_from_client('hello world 2', '2: client -> server')
    pair2.validate_can_send_from_server('hello world 2', '2: server -> client')
    pair2.validate_closing_client_closes_server('closing client 2')
    pair2.cleanup()

    proxy.assert_client_sequence('proxy_client', 'new_proxy_client')
    print_ok("second connection verified with reloaded new_proxy_client cert/key PEM")
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if proxy:
        proxy.shutdown()
