#!/usr/bin/env python3

"""
Tiny fixed-response HTTP backend for the ghostunnel benchmark suite.

Sits behind a ghostunnel *server* instance: ghostunnel terminates TLS/mTLS and
forwards plain HTTP here. Kept deliberately minimal (precomputed body, logging
disabled, threaded) so it is never the bottleneck relative to ghostunnel's TLS
work. See bench/PLAN.md for the topology.

Usage:
    http_backend.py --port PORT [--size BYTES]

Prints "READY" to stdout once listening (so the orchestrator can sync without
polling), then serves until terminated.
"""

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def make_handler(body: bytes):
    class Handler(BaseHTTPRequestHandler):
        # Advertise HTTP/1.1 so keep-alive works (vegeta -keepalive=true).
        protocol_version = "HTTP/1.1"

        def _respond(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def do_GET(self):
            self._respond()

        def do_HEAD(self):
            self._respond()

        def do_POST(self):
            # Drain any request body so the connection can be reused.
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(length)
            self._respond()

        def log_message(self, *args):
            pass  # silence per-request logging (it would dominate cost)

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--size", type=int, default=64,
                        help="response body size in bytes")
    args = parser.parse_args()

    body = b"x" * args.size

    # Co-bind with the orchestrator's SO_REUSEPORT reservation (see
    # bench_common.get_free_port) instead of racing for a released port.
    class Server(ThreadingHTTPServer):
        allow_reuse_port = True
        daemon_threads = True

    server = Server((args.host, args.port), make_handler(body))

    sys.stdout.write("READY\n")
    sys.stdout.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
