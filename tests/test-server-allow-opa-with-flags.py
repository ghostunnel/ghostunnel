#!/usr/bin/env python3

"""
Test that --allow-policy combines with other allow flags as a logical OR:
a peer allowed by EITHER the OPA policy OR an allow flag may connect, and a
peer allowed by neither is rejected. Guards the change that made
--allow-policy usable alongside the other --allow-* flags.
"""

from common import LOCALHOST, RootCert, SocketPair, TcpServer, \
    TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
    STATUS_PORT, assert_connection_rejected

from tempfile import mkdtemp
import shutil
import os

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert(
        'server',
        san='DNS:server,IP:127.0.0.1,IP:::1,DNS:localhost')
    # client1 is allowed by the OPA policy (DNS SAN "client1"), not by any flag
    root.create_signed_cert(
        'client1',
        san='DNS:client1,IP:127.0.0.1,IP:::1,DNS:localhost')
    # client2 is allowed by --allow-cn=client2, not by the policy
    root.create_signed_cert(
        'client2',
        san='DNS:client2,IP:127.0.0.1,IP:::1,DNS:localhost')
    # client3 is allowed by neither
    root.create_signed_cert(
        'client3',
        san='DNS:client3,IP:127.0.0.1,IP:::1,DNS:localhost')

    # start ghostunnel with both a policy and an allow flag
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
                                 '--allow-cn=client2',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # client1: allowed by the policy only
    pair1 = SocketPair(
        TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "client1 allowed via policy")
    pair1.cleanup()

    # client2: allowed by --allow-cn only
    pair2 = SocketPair(
        TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair2.validate_can_send_from_client("toto", "client2 allowed via --allow-cn")
    pair2.cleanup()

    # client3: allowed by neither policy nor flag
    assert_connection_rejected(
        TlsClient('client3', 'root', LISTEN_PORT), TcpServer(TARGET_PORT), "client3")

    print_ok("OK")
finally:
    terminate(ghostunnel)
