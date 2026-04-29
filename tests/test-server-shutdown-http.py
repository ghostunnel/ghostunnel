#!/usr/bin/env python3

"""Server-mode /_shutdown endpoint: POST drains and exits, other methods 405."""

import http.client
import socket
import time
import urllib.error
import urllib.request

from common import (LOCALHOST, LISTEN_PORT, STATUS_PORT, TARGET_PORT,
                    SocketPair, TcpServer, TlsClient, create_default_certs,
                    print_ok, start_ghostunnel_server, terminate, urlopen)

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server(extra_args=['--enable-shutdown'])

    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT),
                      TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("toto", "baseline tunnel works")
    pair.cleanup()

    print_ok('GET /_shutdown should be rejected with 405')
    try:
        urlopen("https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT))
        raise Exception("GET /_shutdown unexpectedly succeeded")
    except urllib.error.HTTPError as e:
        if e.code != 405:
            raise Exception("expected 405, got {0}".format(e.code))
        print_ok("GET correctly returned 405")

    print_ok('POST /_shutdown should trigger graceful shutdown')
    req = urllib.request.Request(
        "https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT),
        method='POST')
    try:
        resp = urlopen(req)
        if resp.status != 200:
            raise Exception("expected 200, got {0}".format(resp.status))
        print_ok("POST returned 200")
    except http.client.RemoteDisconnected:
        print_ok("POST connection closed by server (also acceptable)")

    stopped = False
    for _ in range(30):
        if ghostunnel.poll() is not None:
            stopped = True
            break
        time.sleep(1)
    if not stopped:
        raise Exception('ghostunnel did not terminate within 30s')
    if ghostunnel.returncode != 0:
        raise Exception('non-zero exit: {0}'.format(ghostunnel.returncode))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((LOCALHOST, LISTEN_PORT))
        raise Exception('listen port still accepting after shutdown')
    except (ConnectionRefusedError, OSError):
        print_ok("listen port correctly refuses connections post-shutdown")
    finally:
        s.close()

    print_ok("OK (terminated)")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
