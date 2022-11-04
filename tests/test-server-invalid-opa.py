#!/usr/bin/env python3

"""
Tests code paths with invalid policy.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, \
    TlsClient, print_ok, run_ghostunnel, terminate

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
        shutil.copyfile(dir_path + '/test-server-allow-opa.rego', tmp_dir + '/policy.rego')

        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-policy=' + tmp_dir + '/policy.rego',
                                     '--allow-query=xxx@invalid',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # wait for ghostunnel to exit and make sure error code is not zero
        ret = ghostunnel.wait(timeout=10)
        if ret == 0:
            raise Exception(
                'ghostunnel terminated with zero, though flags were invalid')
        else:
            print_ok("OK (terminated)")
    finally:
        terminate(ghostunnel)
