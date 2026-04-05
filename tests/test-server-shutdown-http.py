#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, urlopen, LISTEN_PORT, TARGET_PORT
import http.client
import urllib.request
import urllib.error
import urllib.parse
import time
import os

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        root.create_signed_cert('client')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=client',
                                     '--enable-shutdown',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # wait for startup
        TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

        # create connections with client
        pair1 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.cleanup()

        print_ok('attempting to terminate ghostunnel via HTTP POST')
        try:
            urlopen(urllib.request.Request("https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT), method='POST'))
        except http.client.RemoteDisconnected:
            pass  # expected: server may close before sending response

        stopped = False
        for _ in range(90):
            try:
                try:
                    ghostunnel.wait(timeout=1)
                except Exception:
                    pass
                os.kill(ghostunnel.pid, 0)
                print_ok("ghostunnel is still alive")
            except Exception:
                stopped = True
                break
            time.sleep(1)

        if not stopped:
            raise Exception('ghostunnel did not terminate within 90 seconds')

        print_ok("OK (terminated)")
    finally:
        terminate(ghostunnel)
