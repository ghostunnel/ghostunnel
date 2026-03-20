#!/usr/bin/env python3

"""
Tests that verify-policy flag works correctly on the client.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
    TlsServer, print_ok, run_ghostunnel, status_info, terminate, wait_for_status, LISTEN_PORT, TARGET_PORT

from tempfile import mkstemp, mkdtemp
import signal
import shutil
import ssl
import os

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')
        root.create_signed_cert(
            'server1',
            san='DNS:server1,IP:127.0.0.1,IP:::1,DNS:localhost')
        root.create_signed_cert(
            'server2',
            san='DNS:server2,IP:127.0.0.1,IP:::1,DNS:localhost')

        other_root = RootCert('other_root')
        other_root.create_signed_cert('other_server')

        # start ghostunnel
        dir_path = os.path.dirname(os.path.realpath(__file__))
        tmp_dir = mkdtemp()
        shutil.copyfile(dir_path + '/test-client-verify-opa-policy.tar.gz', tmp_dir + '/bundle.tar.gz')

        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target=localhost:{0}'.format(TARGET_PORT),
                                     '--keystore=client.p12',
                                     '--verify-policy=' + tmp_dir + '/bundle.tar.gz',
                                     '--verify-query=data.policy.allow',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # connect to server1, confirm that the tunnel is up
        pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
            'server1', 'root', TARGET_PORT))
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_closing_client_closes_server(
            "1: client closed -> server closed")

        # connect to server2, confirm that the tunnel isn't up
        try:
            pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
                'server2', 'root', TARGET_PORT))
            raise Exception('failed to reject other_server')
        except ssl.SSLError:
            print_ok("other_server correctly rejected")

        # Change policy and reload
        shutil.copyfile(dir_path + '/test-allow-all-policy.tar.gz', tmp_dir + '/bundle.tar.gz')
        pre_reload = status_info().get('last_reload')
        ghostunnel.send_signal(signal.SIGUSR1)

        # wait until reload complete
        wait_for_status(lambda info: info.get('last_reload') != pre_reload)
        print_ok("reloaded policy")

        # Should work with server2 now
        pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
            'server2', 'root', TARGET_PORT))
        pair.validate_can_send_from_client(
            "hello world", "2: client -> server")
        pair.validate_can_send_from_server(
            "hello world", "2: server -> client")
        pair.validate_closing_client_closes_server(
            "2: client closed -> server closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
