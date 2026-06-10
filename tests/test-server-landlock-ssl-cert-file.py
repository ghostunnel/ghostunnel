#!/usr/bin/env python3

"""
Linux-only regression test for landlock env-derived rules.

Two variants exercise code paths that are otherwise only covered by unit
tests of the rule-building helpers:

1. SSL_CERT_FILE FS rule (landlock_linux.go around lines 107-117): start a
   server WITHOUT --cacert, instead pointing Go's system trust store at the
   generated test root via SSL_CERT_FILE. The handshake succeeds only if
   landlock's per-env-var FS rule allows the server to read the bundle.

2. HTTPS_PROXY net rule (landlock_linux.go around lines 199-206): re-run the
   HTTP CONNECT proxy data path (the proxy URL is supplied via --connect-proxy
   as usual) while also exporting HTTPS_PROXY in the child env, so the env-
   derived ConnectTCP rule gets installed. We just need the tunnel to keep
   working — a malformed env rule would cause RestrictNet/RestrictPaths
   setup to fail.

On kernels without landlock support the rules are no-ops, so the test still
passes there. The value lands on modern CI kernels (and in Docker tests).
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
                   TcpServer, TlsClient, TlsServer, print_ok, run_ghostunnel, \
                   require_platform, terminate, LISTEN_PORT, TARGET_PORT, \
                   get_free_port
import http.server
import os
import select
import shutil
import tempfile
import threading

require_platform('Linux')

FAKE_TARGET = "qKOjftPTxW"


class FakeConnectProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        try:
            host, port = self.path.split(':')
            if host != FAKE_TARGET:
                raise Exception(
                    'proxy target must be fake target, but was: ' + self.path)
            print_ok("got proxy request, with proxy target: " + self.path)
            socket = TcpClient(int(port))
            socket.connect(attempts=5)
            self.wfile.write(
                bytearray("HTTP/1.1 200 Connection established\r\n", "utf-8"))
            self.wfile.write(
                bytearray(
                    "Proxy-agent: FakeConnectProxyHandler\r\n\r\n",
                    "utf-8"))
            remote = socket.get_socket()
            rlist = [self.connection, remote]
            for _ in range(1000):
                reads, _, errs = select.select(rlist, [], rlist, 10)
                if errs:
                    print_ok("got error in select(): " + str(errs))
                    break
                for s in reads:
                    data = s.recv(8192)
                    if data:
                        print_ok("proxy is sending/receiving " +
                                 str(len(data)) + " bytes")
                        (self.connection if s == remote else remote).send(data)
        finally:
            print_ok("connect proxy is done")
            try:
                socket.cleanup()
                self.connection.close()
            except Exception:
                # best-effort cleanup: ignore errors if sockets already gone
                pass


def run_server_variant(root):
    """Variant 1: server without --cacert; rely on SSL_CERT_FILE."""
    ghostunnel = None
    saved = os.environ.get('SSL_CERT_FILE')
    bundle_dir = None
    try:
        # Stash the CA bundle in a dedicated directory NOT covered by any
        # other landlock rule. The keystore/certPath flags would otherwise
        # grant RO on the cwd (filepath.Dir("server.p12") == "."), masking a
        # missing SSL_CERT_FILE rule. By placing the bundle outside the cwd,
        # the SSL_CERT_FILE rule is the only thing that can let the server
        # read it.
        # Use GHOSTUNNEL_TEST_TMPDIR when set (Docker test runner exports it,
        # pointing at /var/...). Outside Docker we fall back to /tmp, where
        # the SSL_CERT_FILE FS rule is masked by defaultReadWritePaths — that
        # is acceptable: the test is most valuable in the Docker/Linux CI
        # path where landlock per-rule installation actually matters.
        parent = os.environ.get('GHOSTUNNEL_TEST_TMPDIR') or None
        bundle_dir = tempfile.mkdtemp(
            prefix='ghostunnel-ssl-cert-file-', dir=parent)
        bundle_path = os.path.join(bundle_dir, 'root.crt')
        shutil.copyfile('root.crt', bundle_path)
        os.environ['SSL_CERT_FILE'] = bundle_path

        ghostunnel = run_ghostunnel([
            'server',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
            '--keystore=server.p12',
            # No --cacert: certloader.LoadTrustStore falls back to
            # x509.SystemCertPool(), which on Linux honors SSL_CERT_FILE.
            '--allow-ou=client',
            '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
        ])

        pair = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_client(
            'hello-ssl-cert-file', 'SSL_CERT_FILE: client -> server')
        pair.validate_can_send_from_server(
            'hello-ssl-cert-file', 'SSL_CERT_FILE: server -> client')
        pair.cleanup()
        print_ok("SSL_CERT_FILE variant OK")
    finally:
        terminate(ghostunnel)
        if saved is None:
            os.environ.pop('SSL_CERT_FILE', None)
        else:
            os.environ['SSL_CERT_FILE'] = saved
        if bundle_dir is not None:
            shutil.rmtree(bundle_dir, ignore_errors=True)


def run_proxy_variant(root):
    """Variant 2: client mode through --connect-proxy with HTTPS_PROXY in env.

    HTTPS_PROXY is only consumed by Go's net/http (for ACME etc.), but
    setupLandlock unconditionally inspects it and installs a ConnectTCP rule.
    A bad value would cause setupLandlock to error out, killing ghostunnel
    before it can listen.
    """
    ghostunnel = None
    saved = os.environ.get('HTTPS_PROXY')
    try:
        proxy_port = get_free_port(release=True)
        httpd = http.server.HTTPServer(
            (LOCALHOST, proxy_port), FakeConnectProxyHandler)
        server = threading.Thread(target=httpd.handle_request)
        server.start()

        # Force the env-derived net rule code path to run with a parseable
        # URL. The port is unrelated to the actual CONNECT proxy used by
        # the data path (which comes from --connect-proxy below).
        os.environ['HTTPS_PROXY'] = 'http://envonly.example.invalid:9999'

        ghostunnel = run_ghostunnel([
            'client',
            '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
            '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
            '--keystore=client.p12',
            '--cacert=root.crt',
            '--connect-proxy=http://{0}:{1}'.format(LOCALHOST, proxy_port),
            '--connect-timeout=30s',
            '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
        ])

        pair = SocketPair(
            TcpClient(LISTEN_PORT),
            TlsServer('server-fake', 'root', TARGET_PORT))
        pair.validate_can_send_from_client(
            'hello-https-proxy', 'HTTPS_PROXY: client -> server')
        pair.validate_can_send_from_server(
            'hello-https-proxy', 'HTTPS_PROXY: server -> client')
        pair.validate_closing_client_closes_server('closing client')
        pair.cleanup()
        print_ok("HTTPS_PROXY variant OK")
    finally:
        terminate(ghostunnel)
        if saved is None:
            os.environ.pop('HTTPS_PROXY', None)
        else:
            os.environ['HTTPS_PROXY'] = saved


# create certs (shared by both variants)
root = RootCert('root')
root.create_signed_cert('server')
root.create_signed_cert('client')
# A signed cert with the FAKE_TARGET hostname is needed for the proxy
# variant's backend TlsServer (the tunnel client expects SNI=FAKE_TARGET).
root.create_signed_cert('server-fake',
                        san='DNS:{0},IP:127.0.0.1'.format(FAKE_TARGET))

run_server_variant(root)
run_proxy_variant(root)

print_ok("OK")
