#!/usr/bin/env python3

"""
Test to check --allow-policy flag behavior.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, \
    TlsClient, print_ok, run_ghostunnel, terminate, status_info

from tempfile import mkstemp, mkdtemp
import time
import signal
import shutil
import ssl
import socket
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
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-policy=' + tmp_dir + '/bundle.tar.gz',
                                     '--allow-query=data.policy.allow',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # create connections with client
        pair1 = SocketPair(
            TlsClient('client1', 'root', 13001), TcpServer(13002))
        pair1.validate_can_send_from_client("toto", "pair1 works")
        pair1.validate_can_send_from_server

        try:
            pair2 = SocketPair(
                TlsClient('client2', 'root', 13001), TcpServer(13002))
            raise Exception('failed to reject client2')
        except (ssl.SSLError, socket.timeout):
            print_ok("client2 correctly rejected")

        # Change policy and reload
        shutil.copyfile(dir_path + '/test-allow-all-policy.tar.gz', tmp_dir + '/bundle.tar.gz')
        ghostunnel.send_signal(signal.SIGUSR1)

        # wait until reload complete
        while 'last_reload' not in status_info():
            os.sleep(1)
        print_ok("reloaded policy")

        # Should work with client2 now
        pair1 = SocketPair(
            TlsClient('client2', 'root', 13001), TcpServer(13002))
        pair1.validate_can_send_from_client("toto", "pair2 works")
        pair1.validate_can_send_from_server

        print_ok("OK")
    finally:
        terminate(ghostunnel)
