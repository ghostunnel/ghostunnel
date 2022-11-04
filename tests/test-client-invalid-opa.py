#!/usr/bin/env python3

"""
Tests code paths with invalid policy.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, \
    TlsServer, print_ok, run_ghostunnel, terminate

from tempfile import mkstemp, mkdtemp
import time
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
        shutil.copyfile(dir_path + '/test-client-verify-opa.rego', tmp_dir + '/policy.rego')

        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target=localhost:13002',
                                     '--keystore=client.p12',
                                     '--verify-policy=' + tmp_dir + '/policy.rego',
                                     '--verify-query=xxx@invalid',
                                     '--cacert=root.crt',
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
