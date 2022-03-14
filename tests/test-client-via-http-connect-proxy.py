#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate
import http.server
import threading
import select

# We deliberately use an unresolvable address in this test
# to verify that Ghostunnel accepts unknown targets when
# a connect proxy is used (a target may not be known
# internally, only externally to the proxy).
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
            for _ in range(0, 1000):
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
                socket.get_socket().shutdown()
                socket.cleanup()
                self.connection.close()
            except BaseException:
                pass


if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server', san='DNS:{}'.format(FAKE_TARGET))
        root.create_signed_cert('client')

        httpd = http.server.HTTPServer(
            (LOCALHOST, 13080), FakeConnectProxyHandler)
        server = threading.Thread(target=httpd.handle_request)
        server.start()

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(FAKE_TARGET),
                                     '--keystore=client.p12',
                                     '--cacert=root.crt',
                                     '--connect-proxy=http://{0}:13080'.format(LOCALHOST),
                                     '--connect-timeout=30s',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect to server, confirm that the tunnel is up
        pair = SocketPair(TcpClient(13001), TlsServer('server', 'root', 13002))
        pair.validate_can_send_from_client(
            'hello world', '1: client -> server')
        pair.validate_can_send_from_server(
            'hello world', '1: server -> client')
        pair.validate_closing_client_closes_server('closing client')
        pair.cleanup()

        print_ok("OK")
    finally:
        terminate(ghostunnel)
