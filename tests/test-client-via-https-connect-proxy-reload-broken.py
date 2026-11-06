#!/usr/bin/env python3

"""
Ensures that a reload with a broken proxy credential on disk keeps the
previously loaded proxy client certificate, so that the tunnel keeps
working through an HTTPS CONNECT proxy that requires client certificates.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsClient, TlsServer, print_ok, reload_args, reload_and_wait, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, FakeConnectProxy

ghostunnel = None
proxy = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')

    proxy_root = RootCert('proxy_root')
    proxy_root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')
    proxy_root.create_signed_cert('proxy_client', p12_password=None)

    proxy = FakeConnectProxy(certfile='proxy.crt', keyfile='proxy.key',
                             cafile='proxy_root.crt', require_client_cert=True)

    # start ghostunnel
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
    proxy.assert_client_sequence('proxy_client')

    # replace the proxy certificate with an empty file and reload
    open('proxy_client.crt', 'w').close()
    reload_and_wait(ghostunnel, timeout=30)

    # the main credential reloaded fine and is still served on the status port
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'client')
    print_ok("got client on /_status after reload")

    # new tunnel connections must still use the old proxy certificate
    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair2.validate_can_send_from_client('hello world 2', '2: client -> server')
    pair2.validate_can_send_from_server('hello world 2', '2: server -> client')
    pair2.cleanup()
    proxy.assert_client_sequence('proxy_client')

    # ensure that pair1 is still alive
    pair1.validate_can_send_from_client('hello world 1', '1: client -> server still works')
    pair1.cleanup()
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if proxy:
        proxy.shutdown()
