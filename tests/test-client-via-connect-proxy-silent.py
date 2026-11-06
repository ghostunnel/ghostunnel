#!/usr/bin/env python3

"""
Ensures that --connect-timeout bounds the CONNECT exchange with an HTTP or
HTTPS CONNECT proxy: a proxy that accepts the connection (and completes the
TLS handshake, for https://) but never answers the CONNECT request must not
hang the dial. Both the status endpoint's backend check and a tunnel
connection must fail within roughly --connect-timeout.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, print_ok, run_ghostunnel, terminate, wait_for_status, LISTEN_PORT, TARGET_PORT
from connect_proxy import FAKE_TARGET, SilentProxy
import json
import ssl
import time
import urllib.error
import urllib.request

CONNECT_TIMEOUT = 2
# Generous upper bound: well above --connect-timeout, well below "hangs".
MAX_ELAPSED = 10

BASE_ARGS = ['client',
             '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
             '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
             '--keystore=client.p12',
             '--cacert=root.crt',
             '--connect-timeout={0}s'.format(CONNECT_TIMEOUT),
             '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]


def timed_status():
    """Fetch /_status with a client-side timeout, returning (info, seconds)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)
    start = time.time()
    try:
        body = urllib.request.urlopen(url, context=ctx, timeout=MAX_ELAPSED * 2).read()
    except urllib.error.HTTPError as e:
        body = e.read()
    return json.loads(body), time.time() - start


def expect_bounded(proxy, extra_args):
    ghostunnel = run_ghostunnel(BASE_ARGS + ['--proxy=' + proxy.url()] + extra_args)
    try:
        # wait until ghostunnel is up and has tried the backend once
        wait_for_status(lambda info: info.get('backend_error'), timeout=60)

        info, elapsed = timed_status()
        if info['backend_ok']:
            raise Exception('backend check should have failed: ' + str(info))
        if 'timeout' not in info['backend_error']:
            raise Exception('expected a timeout backend error, got: ' + info['backend_error'])
        if elapsed > MAX_ELAPSED:
            raise Exception('backend check took {0:.1f}s, expected about {1}s'.format(
                elapsed, CONNECT_TIMEOUT))
        print_ok("backend check timed out after {0:.1f}s: {1}".format(
            elapsed, info['backend_error']))

        # a tunnel connection must be closed instead of hanging
        client = TcpClient(LISTEN_PORT)
        client.connect(attempts=5)
        sock = client.get_socket()
        sock.settimeout(MAX_ELAPSED * 2)
        start = time.time()
        try:
            data = sock.recv(1)
        except ConnectionResetError:
            data = b''
        elapsed = time.time() - start
        sock.close()
        if data:
            raise Exception('tunnel connection unexpectedly received data')
        if elapsed > MAX_ELAPSED:
            raise Exception('tunnel connection closed after {0:.1f}s, expected about {1}s'.format(
                elapsed, CONNECT_TIMEOUT))
        print_ok("tunnel connection closed after {0:.1f}s".format(elapsed))
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

    proxy = SilentProxy()
    proxies.append(proxy)
    expect_bounded(proxy, [])
    print_ok("silent http proxy bounded by --connect-timeout")

    proxy = SilentProxy(certfile='proxy.crt', keyfile='proxy.key')
    proxies.append(proxy)
    expect_bounded(proxy, ['--proxy-cacert=proxy_root.crt'])
    print_ok("silent https proxy bounded by --connect-timeout")

    print_ok("OK")
finally:
    for proxy in proxies:
        proxy.shutdown()
