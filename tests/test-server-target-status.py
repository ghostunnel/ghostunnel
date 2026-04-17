#!/usr/bin/env python3

"""
Tests that --target-status flag enables HTTP health checking of the backend,
and that /_status reflects backend health.

Note: ghostunnel's --target-status HTTP client uses the backend dialer (i.e.
it connects to --target and sends the HTTP request from --target-status).
So the health HTTP server must be reachable at the --target address.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, print_ok, \
                   run_ghostunnel, terminate, wait_for_status, \
                   LISTEN_PORT, get_free_port
import http.server
import socket
import threading

ghostunnel = None
health_server = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # Allocate a fresh port for the health server and keep the reservation.
    # ReuseHTTPServer enables SO_REUSEPORT in server_bind(), so it can bind
    # safely without reopening a port-collision race in parallel test runs.
    BACKEND_PORT = get_free_port()

    # start a simple HTTP server for health checks.
    # ghostunnel's --target-status HTTP client dials --target to send
    # the health check request, so the HTTP server must live there.
    class HealthHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'OK')
        def log_message(self, format, *args):
            pass  # suppress logs

    class ReuseHTTPServer(http.server.HTTPServer):
        allow_reuse_address = True
        def server_bind(self):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            so_reuseport = getattr(socket, 'SO_REUSEPORT', None)
            if so_reuseport is not None:
                self.socket.setsockopt(socket.SOL_SOCKET, so_reuseport, 1)
            super().server_bind()

    health_server = ReuseHTTPServer((LOCALHOST, BACKEND_PORT), HealthHandler)
    health_thread = threading.Thread(target=health_server.serve_forever)
    health_thread.daemon = True
    health_thread.start()
    print_ok("health check server started on port {0}".format(BACKEND_PORT))

    # start ghostunnel with --target-status pointing at a health endpoint
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, BACKEND_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--target-status=http://{0}:{1}/healthz'.format(LOCALHOST, BACKEND_PORT),
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # wait for ghostunnel status port to come up
    TcpClient(STATUS_PORT).connect(20)

    # verify status is OK
    wait_for_status(lambda s: s.get('ok') is True)
    print_ok("/_status reports ok=true with healthy backend")

    # stop the health check server and close the listening socket
    health_server.shutdown()
    health_server.server_close()
    health_server = None
    print_ok("health check server stopped")

    # wait for /_status to report not-ok
    wait_for_status(lambda s: s.get('ok') is False)
    print_ok("/_status reports ok=false after backend health check fails")

    # restart the health check server on the same port
    health_server = ReuseHTTPServer((LOCALHOST, BACKEND_PORT), HealthHandler)
    health_thread = threading.Thread(target=health_server.serve_forever)
    health_thread.daemon = True
    health_thread.start()
    print_ok("health check server restarted on port {0}".format(BACKEND_PORT))

    # wait for /_status to recover
    wait_for_status(lambda s: s.get('ok') is True)
    print_ok("/_status reports ok=true after backend recovery")

    print_ok("OK")
finally:
    if health_server:
        health_server.shutdown()
        health_server.server_close()
    terminate(ghostunnel)
