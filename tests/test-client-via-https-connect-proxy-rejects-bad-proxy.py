#!/usr/bin/env python3

"""
Ensures that client mode refuses to tunnel through an HTTPS CONNECT proxy
that fails TLS verification, and fails cleanly when the proxy demands a
client certificate that Ghostunnel does not have:

- proxy certificate issued by a CA that is not in --proxy-cacert.
- proxy certificate that does not match the proxy hostname.
- proxy requires a client certificate but no --proxy-* credential is set.

In each case no CONNECT request may reach the proxy and no tunnel connection
may reach the target.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate, wait_for_status, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, FakeConnectProxy

BASE_ARGS = ['client',
             '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
             '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
             '--keystore=client.p12',
             '--cacert=root.crt',
             '--connect-timeout=5s',
             '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]


def expect_proxy_rejected(proxy, extra_args, expected_error, msg):
    """Start ghostunnel against proxy and check that dialing through it
    fails with expected_error, as reported by the status endpoint, which
    dials the target through the proxy on every request."""
    ghostunnel = run_ghostunnel(BASE_ARGS + ['--proxy=' + proxy.url()] + extra_args)
    try:
        info = wait_for_status(lambda info: info.get('backend_error'))
        if info['backend_ok']:
            raise Exception('backend check should have failed: ' + str(info))
        if expected_error not in info['backend_error']:
            raise Exception('expected backend error containing "{0}", got: {1}'.format(
                expected_error, info['backend_error']))
        print_ok("backend check failed as expected: " + info['backend_error'])

        # a tunnel connection must not make it to the target either
        try:
            SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT), timeout=5)
            raise Exception('tunnel connection should not have reached the target')
        except TimeoutError:
            print_ok("tunnel connection did not reach the target")

        if proxy.seen_clients:
            raise Exception('proxy should not have received any CONNECT request, got: '
                            + str(proxy.seen_clients))
        print_ok(msg)
    finally:
        terminate(ghostunnel)


proxies = []
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')

    proxy_root = RootCert('proxy_root')
    proxy_root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')
    proxy_root.create_signed_cert('proxy_wrong_name', san='DNS:proxy.invalid,IP:192.0.2.1')

    other_root = RootCert('other_root')
    other_root.create_signed_cert('rogue_proxy', san='DNS:localhost,IP:127.0.0.1')

    # proxy certificate from a CA that is not trusted for the proxy
    proxy = FakeConnectProxy(certfile='rogue_proxy.crt', keyfile='rogue_proxy.key')
    proxies.append(proxy)
    expect_proxy_rejected(proxy, ['--proxy-cacert=proxy_root.crt'],
                          'certificate signed by unknown authority',
                          'proxy with untrusted certificate rejected')

    # proxy certificate that does not match the proxy address
    proxy = FakeConnectProxy(certfile='proxy_wrong_name.crt', keyfile='proxy_wrong_name.key')
    proxies.append(proxy)
    expect_proxy_rejected(proxy, ['--proxy-cacert=proxy_root.crt'],
                          'not {0}'.format(LOCALHOST),
                          'proxy with mismatched certificate name rejected')

    # proxy demands a client certificate, but none is configured
    proxy = FakeConnectProxy(certfile='proxy.crt', keyfile='proxy.key',
                             cafile='proxy_root.crt', require_client_cert=True)
    proxies.append(proxy)
    expect_proxy_rejected(proxy, ['--proxy-cacert=proxy_root.crt'],
                          'certificate required',
                          'proxy requiring a client certificate fails without one')

    print_ok("OK")
finally:
    for proxy in proxies:
        proxy.shutdown()
