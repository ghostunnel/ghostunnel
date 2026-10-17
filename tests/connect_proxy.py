"""
Shared helpers for the HTTP(S) CONNECT proxy integration tests.

Not a test itself: the runner only picks up tests/test-*.py.
"""

from common import LOCALHOST, get_free_port, print_ok
import http.server
import select
import socket
import ssl
import threading

# We deliberately use an unresolvable address as the tunnel target to verify
# that Ghostunnel accepts unknown targets when a connect proxy is used (a
# target may not be known internally, only externally to the proxy).
FAKE_TARGET = "qKOjftPTxW"


class FakeConnectProxy:
    """A minimal HTTP CONNECT proxy on a free localhost port.

    With certfile/keyfile the proxy speaks TLS; require_client_cert then
    makes it demand a client certificate signed by cafile. Every accepted
    CONNECT records the client certificate CN (None if the client presented
    no certificate) in seen_clients, so tests can check which credential
    Ghostunnel used to reach the proxy."""

    def __init__(self, certfile=None, keyfile=None, cafile=None,
                 require_client_cert=False):
        self.tls = certfile is not None
        self.seen_clients = []
        self.port = get_free_port(release=True)
        proxy = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self):
                proxy._handle_connect(self)

            def log_message(self, format, *args):
                pass  # suppress default stderr request logging

        # Threaded, so that a tunnel connection held open by a test does not
        # block the status endpoint's backend checks, which also go through
        # the proxy.
        self.httpd = http.server.ThreadingHTTPServer((LOCALHOST, self.port), Handler)
        self.httpd.daemon_threads = True
        if self.tls:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
            if cafile:
                ctx.load_verify_locations(cafile=cafile)
            ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_NONE
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)

        thread = threading.Thread(target=self.httpd.serve_forever)
        thread.daemon = True
        thread.start()
        print_ok("fake {0} connect proxy listening on {1}".format(
            'https' if self.tls else 'http', self.url()))

    def url(self):
        return '{0}://{1}:{2}'.format(
            'https' if self.tls else 'http', LOCALHOST, self.port)

    def shutdown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def assert_client_sequence(self, *expected):
        """Check which client certificates the proxy has seen so far.

        Consecutive duplicates are collapsed, so ('a', 'b') means every
        connection used cert 'a' until some point and cert 'b' from then on,
        regardless of how many connections there were (status checks also
        go through the proxy). Raises if the proxy saw nothing."""
        collapsed = []
        for cn in self.seen_clients:
            if not collapsed or collapsed[-1] != cn:
                collapsed.append(cn)
        if tuple(collapsed) != tuple(expected):
            raise Exception('expected proxy to see client certs {0}, got: {1}'.format(
                expected, self.seen_clients))
        print_ok("proxy saw client certs: {0}".format(collapsed))

    def _handle_connect(self, handler):
        remote = None
        try:
            cn = None
            if self.tls:
                peercert = handler.connection.getpeercert()
                if peercert:
                    subject = dict(x[0] for x in peercert['subject'])
                    cn = subject.get('commonName')
            self.seen_clients.append(cn)
            print_ok("proxy accepted connection from client cert CN: " + str(cn))

            host, port = handler.path.split(':')
            if host != FAKE_TARGET:
                raise Exception(
                    'proxy target must be fake target, but was: ' + handler.path)
            print_ok("got proxy request, with proxy target: " + handler.path)

            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Nothing is listening on the target during the status
            # endpoint's backend checks between connections. The harness
            # keeps that port bound (but not listening) to reserve it, and
            # on macOS a connect to such a port only fails by timing out, so
            # keep the connect timeout short.
            remote.settimeout(1)
            try:
                remote.connect((LOCALHOST, int(port)))
            except Exception:
                remote.close()
                remote = None
                handler.send_error(502, "Bad Gateway")
                return
            remote.settimeout(10)

            handler.wfile.write(
                bytearray("HTTP/1.1 200 Connection established\r\n", "utf-8"))
            handler.wfile.write(
                bytearray("Proxy-agent: FakeConnectProxy\r\n\r\n", "utf-8"))
            rlist = [handler.connection, remote]
            for _ in range(1000):
                reads, _, errs = select.select(rlist, [], rlist, 10)
                if errs:
                    print_ok("got error in select(): " + str(errs))
                    break
                for s in reads:
                    data = s.recv(8192)
                    if data:
                        (handler.connection if s == remote else remote).send(data)
        finally:
            print_ok("connect proxy is done")
            try:
                if remote:
                    remote.close()
                handler.connection.close()
            except Exception:
                pass  # best-effort cleanup of proxy sockets
