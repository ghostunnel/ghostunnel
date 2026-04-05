#!/usr/bin/env python3

"""
Test to check --allow-policy flag behavior.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, \
    TlsClient, print_ok, run_ghostunnel, status_info, terminate, wait_for_status, LISTEN_PORT, TARGET_PORT, \
    assert_connection_rejected

from tempfile import mkdtemp
import signal
import shutil
import os

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert(
            'server',
            san='DNS:server,IP:127.0.0.1,IP:::1,DNS:localhost')
        root.create_signed_cert(
            'client1',
            san='DNS:client1,IP:127.0.0.1,IP:::1,DNS:localhost')
        root.create_signed_cert(
            'client2',
            san='DNS:client2,IP:127.0.0.1,IP:::1,DNS:localhost')

        # start ghostunnel
        dir_path = os.path.dirname(os.path.realpath(__file__))
        tmp_dir = mkdtemp()
        shutil.copyfile(dir_path + '/test-server-allow-opa-policy.tar.gz', tmp_dir + '/bundle.tar.gz')

        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-policy=' + tmp_dir + '/bundle.tar.gz',
                                     '--allow-query=data.policy.allow',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # create connections with client
        pair1 = SocketPair(
            TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.validate_can_send_from_server("toto", "pair1 reverse works")

        assert_connection_rejected(
            TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT), "client2")

        # Change policy and reload
        shutil.copyfile(dir_path + '/test-allow-all-policy.tar.gz', tmp_dir + '/bundle.tar.gz')
        pre_reload = status_info().get('last_reload')
        ghostunnel.send_signal(signal.SIGUSR1)

        # wait until reload complete
        wait_for_status(lambda info: info.get('last_reload') != pre_reload)
        print_ok("reloaded policy")

        # Should work with client2 now
        pair1 = SocketPair(
            TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair1.validate_can_send_from_client("toto", "pair2 works")
        pair1.validate_can_send_from_server("toto", "pair1 reverse works after reload")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
