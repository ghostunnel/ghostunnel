#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, reload_args, run_ghostunnel, terminate, trigger_reload, LISTEN_PORT, TARGET_PORT, get_free_port
import http.server
import threading
import select
import ssl
import os
import time

FAKE_TARGET = "qKOjftPTxW"
seen_proxy_clients = []

class FakeHttpsConnectProxyHandler(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        try:
            peercert = self.connection.getpeercert()
            subject = dict(x[0] for x in peercert['subject'])
            cn = subject.get('commonName')
            print_ok("proxy accepted mTLS connection from client CN: " + str(cn))
            seen_proxy_clients.append(cn)

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
                    "Proxy-agent: FakeHttpsConnectProxyHandler\r\n\r\n",
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
                        (self.connection if s == remote else remote).send(data)
        finally:
            print_ok("connect proxy is done")
            try:
                socket.get_socket().shutdown()
                socket.cleanup()
                self.connection.close()
            except Exception:
                pass  # best-effort cleanup of proxy sockets

    def log_message(self, format, *args):
        # suppress default stderr request logging
        pass


ghostunnel = None
httpd = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
    root.create_signed_cert('client')
    root.create_signed_cert('proxy', san='DNS:localhost,IP:127.0.0.1')
    root.create_signed_cert('proxy_client', p12_password='testpass')
    root.create_signed_cert('new_proxy_client', p12_password='testpass')

    proxy_port = get_free_port(release=True)
    httpd = http.server.HTTPServer(
        (LOCALHOST, proxy_port), FakeHttpsConnectProxyHandler)

    # configure mTLS on proxy server
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(certfile='proxy.crt', keyfile='proxy.key')
    ssl_ctx.load_verify_locations(cafile='root.crt')
    ssl_ctx.verify_mode = ssl.CERT_REQUIRED
    httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)

    server = threading.Thread(target=httpd.serve_forever)
    server.daemon = True
    server.start()

    # start ghostunnel with proxy keystore
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--proxy=https://{0}:{1}'.format(LOCALHOST, proxy_port),
                                 '--proxy-keystore=proxy_client.p12',
                                 '--proxy-storepass=testpass',
                                 '--connect-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]
                                + reload_args())

    # connect to server, confirm that the tunnel is up
    pair1 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair1.validate_can_send_from_client(
        'hello world 1', '1: client -> server')
    pair1.validate_can_send_from_server(
        'hello world 1', '1: server -> client')
    pair1.validate_closing_client_closes_server('closing client 1')
    pair1.cleanup()

    if len(seen_proxy_clients) != 1 or seen_proxy_clients[0] != 'proxy_client':
        raise Exception('expected proxy to see proxy_client, got: ' + str(seen_proxy_clients))

    print_ok("first connection verified with proxy_client cert")

    # test hot-reload: replace proxy keystore with new_proxy_client.p12
    os.replace('new_proxy_client.p12', 'proxy_client.p12')
    trigger_reload(ghostunnel)
    time.sleep(1)

    pair2 = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair2.validate_can_send_from_client(
        'hello world 2', '2: client -> server')
    pair2.validate_can_send_from_server(
        'hello world 2', '2: server -> client')
    pair2.validate_closing_client_closes_server('closing client 2')
    pair2.cleanup()

    if len(seen_proxy_clients) != 2 or seen_proxy_clients[1] != 'new_proxy_client':
        raise Exception('expected proxy to see new_proxy_client after reload, got: ' + str(seen_proxy_clients))

    print_ok("second connection verified with reloaded new_proxy_client cert")
    print_ok("OK")
finally:
    terminate(ghostunnel)
    if httpd:
        httpd.shutdown()
        httpd.server_close()
