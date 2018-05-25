#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that tunnel sees & reloads certificate changes.
#
# There are various cases to take into account:
# - tunnel picks up client cert change and connects with new cert.
# - tunnel picks up ca change and connects to other_server.
# - tunnel picks up client cert change and uses it on the status port.

from common import *
import os
import signal

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root1 = RootCert('root1')
        root1.create_signed_cert('server1')
        root1.create_signed_cert('client1')

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client1.p12',
                                     '--cacert=root1.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # ensure ghostunnel connects with server1
        pair1 = SocketPair(TcpClient(13001), TlsServer(
            'server1', 'root1', 13002))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.validate_client_cert("client1", "pair1: ou=client1 -> ...")

        # check certificate on status port
        TlsClient(None, 'root1', STATUS_PORT).connect(20, 'client1')
        print_ok("got client1 on /_status")

        # replace keystore with invalid/empty file and reload
        open('new_client1.p12', 'a').close()
        os.rename('new_client1.p12', 'client1.p12')
        ghostunnel.send_signal(signal.SIGUSR1)

        # should still be using old cert
        TlsClient(None, 'root1', STATUS_PORT).connect(20, 'client1')
        print_ok("reload done")

        pair2 = SocketPair(TcpClient(13001), TlsServer(
            'server1', 'root1', 13002))
        pair2.validate_can_send_from_client("toto", "pair2 works")
        pair2.validate_client_cert("client1", "pair2: ou=client1 -> ...")
        pair2.cleanup()

        # ensure that pair1 is still alive
        pair1.validate_can_send_from_client("toto", "pair1 still works")
        pair1.cleanup()
        print_ok("OK")

    finally:
        terminate(ghostunnel)
