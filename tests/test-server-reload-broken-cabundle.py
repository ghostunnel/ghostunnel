#!/usr/bin/env python3

"""
Ensures that when a CA bundle file is corrupted between reloads, ghostunnel
gracefully fails the reload and keeps serving with the previously loaded
trust store. Complements test-server-reload-broken-certificate.py, which
exercises the X509KeyPair parse failure branch; this test exercises the
LoadTrustStore failure branch (certloader/keystore.go ~line 94).
"""

from common import (
    LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient,
    print_ok, reload_args, run_ghostunnel, terminate, trigger_reload,
    LISTEN_PORT, TARGET_PORT,
)
import os
import shutil

ghostunnel = None
try:
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)]
                                + reload_args())

    pair1 = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("baseline", "pair1 baseline works")
    pair1.validate_tunnel_ou("server", "pair1 -> ou=server")

    shutil.copyfile('root.crt', 'root_good.crt')

    with open('new_root.crt', 'wb') as f:
        f.write(b'this is not a pem file at all, garbage bytes\n')
    os.replace('new_root.crt', 'root.crt')
    trigger_reload(ghostunnel)

    TlsClient(None, 'root_good', STATUS_PORT).connect(20, 'server')
    print_ok("status port still serving after failed reload")

    pair2 = SocketPair(
        TlsClient('client', 'root_good', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair2.validate_can_send_from_client("after-failed-reload",
                                        "pair2 works using stale CA pool")
    pair2.validate_tunnel_ou("server", "pair2 -> ou=server")
    pair2.cleanup()

    pair1.validate_can_send_from_client("still-here",
                                        "pair1 still works post-failed-reload")
    pair1.cleanup()

    print_ok("OK")
finally:
    terminate(ghostunnel)
