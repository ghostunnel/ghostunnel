#!/usr/bin/env python3

"""
Test to check OPA policy reloading failure.
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

if __name__ == '__main__':
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
        shutil.copyfile(dir_path + '/test-server-allow-opa.rego', tmp_dir + '/policy.rego')

        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-policy=' + tmp_dir + '/policy.rego',
                                     '--allow-query=data.policy.allow',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # create connections with client
        pair1 = SocketPair(
            TlsClient('client1', 'root', 13001), TcpServer(13002))
        pair1.validate_can_send_from_client('toto', 'pair1 works')
        pair1.validate_can_send_from_server

        try:
            pair2 = SocketPair(
                TlsClient('client2', 'root', 13001), TcpServer(13002))
            raise Exception('failed to reject client2')
        except (ssl.SSLError, socket.timeout):
            print_ok('client2 correctly rejected')

        # make policy invalid and reload
        os.remove(tmp_dir + '/policy.rego')
        ghostunnel.send_signal(signal.SIGUSR1)

        # wait until reload complete
        while 'last_reload' not in status_info():
            os.sleep(1)

        # old policy remains in effect
        pair1 = SocketPair(
            TlsClient('client1', 'root', 13001), TcpServer(13002))
        pair1.validate_can_send_from_client('toto', 'pair1 works')
        pair1.validate_can_send_from_server

        try:
            pair2 = SocketPair(
                TlsClient('client2', 'root', 13001), TcpServer(13002))
            raise Exception('failed to reject client2')
        except (ssl.SSLError, socket.timeout):
            print_ok('client2 correctly rejected')

        print_ok('OK')
    finally:
        terminate(ghostunnel)
