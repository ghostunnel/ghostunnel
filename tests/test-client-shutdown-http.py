#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsClient, TlsServer, print_ok, run_ghostunnel, terminate
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
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client.p12',
                                     '--cacert=root.crt',
                                     '--enable-shutdown',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        def urlopen(path):
            return urllib.request.urlopen(path, cafile='root.crt')

        # wait for startup
        TlsClient(None, 'root', STATUS_PORT).connect(20, 'client')

        # create connections with client
        pair1 = SocketPair(
            TcpClient(13001), TlsServer('server', 'root', 13002))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.cleanup()

        print_ok('attempting to terminate ghostunnel via HTTP POST')
        urlopen(urllib.request.Request("https://{0}:{1}/_shutdown".format(LOCALHOST, STATUS_PORT), method='POST'))

        for n in range(0, 90):
            try:
                try:
                    ghostunnel.wait(timeout=1)
                except BaseException:
                    pass
                os.kill(ghostunnel.pid, 0)
                print_ok("ghostunnel is still alive")
            except BaseException:
                stopped = True
                break
            time.sleep(1)

        if not stopped:
            raise Exception('ghostunnel did not terminate within 90 seconds')

        print_ok("OK (terminated)")
    finally:
        terminate(ghostunnel)
