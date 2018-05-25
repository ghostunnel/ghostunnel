#!/usr/bin/env python3

# Simulates a hanging handshake, waits for timeout.

from subprocess import Popen
from common import *
import urllib.request
import urllib.error
import urllib.parse
import socket
import ssl
import time
import os
import signal
import json
import sys
import errno

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('new_server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13000'.format(LOCALHOST),
                                     '--target={0}:13001'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--connect-timeout=1s',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect but don't perform handshake
        client = TcpClient(13000)
        client.connect(20)
        client.get_socket().setblocking(False)

        def urlopen(path): return urllib.request.urlopen(
            path, cafile='root.crt')

        # wait until handshake times out
        timeout = False
        for _ in range(0, 20):
            metrics = json.loads(str(urlopen(
                "https://{0}:{1}/_metrics".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))
            timeouts = [m['value']
                        for m in metrics if "accept.timeout" in m['metric']]
            if timeouts[0] > 0:
                print_ok("handshake timed out, as expected")
                timeout = True
                break
            time.sleep(1)

        if not timeout:
            raise Exception("socket still appears to be open after timeout")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
