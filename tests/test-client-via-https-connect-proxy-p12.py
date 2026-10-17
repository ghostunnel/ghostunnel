#!/usr/bin/env python3

"""
Ensures that client mode can authenticate to an HTTPS CONNECT proxy with a
client certificate from a PKCS#12 --proxy-keystore, verifying the proxy
against --cacert when --proxy-cacert is not set, and that a replaced proxy
keystore is picked up on reload.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, reload_args, reload_and_wait, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, FakeConnectProxy
import os

ghostunnel = None
proxy = None
try:
    # create certs. Here the proxy shares the target's PKI, so the proxy is
    # verified against --cacert.
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')
    root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')
    root.create_signed_cert('proxy_client', p12_password='testpass')
    root.create_signed_cert('new_proxy_client', p12_password='testpass')

    proxy = FakeConnectProxy(certfile='proxy.crt', keyfile='proxy.key',
                             cafile='root.crt', require_client_cert=True)

    # start ghostunnel with proxy keystore
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--proxy=' + proxy.url(),
                                 '--proxy-keystore=proxy_client.p12',
                                 '--proxy-storepass=testpass',
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
    print_ok("first connection verified with proxy_client keystore")

    # replace proxy keystore with new_proxy_client.p12 and reload; new
    # connections must present the new certificate
    os.replace('new_proxy_client.p12', 'proxy_client.p12')
    reload_and_wait(ghostunnel, timeout=30)

    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair2.validate_can_send_from_client('hello world 2', '2: client -> server')
    pair2.validate_can_send_from_server('hello world 2', '2: server -> client')
    pair2.validate_closing_client_closes_server('closing client 2')
    pair2.cleanup()

    proxy.assert_client_sequence('proxy_client', 'new_proxy_client')
    print_ok("second connection verified with reloaded new_proxy_client keystore")
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if proxy:
        proxy.shutdown()
