#!/usr/bin/env python3

"""
Tests that --allow-all flag accepts any client with a valid certificate,
regardless of CN/OU/SAN, but still rejects clients with untrusted CAs.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, \
                   TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, \
                   assert_connection_rejected

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client1')
    root.create_signed_cert(
            'client2',
            san='DNS:other-client,IP:127.0.0.1,IP:::1,DNS:localhost')

    # create a cert signed by a different CA (not trusted by ghostunnel)
    other_root = RootCert('other_root')
    other_root.create_signed_cert('untrusted_client')

    # create a combined CA bundle so the untrusted client can verify the
    # server cert (signed by root) while presenting its own cert (signed
    # by other_root)
    with open('combined_ca.crt', 'w') as f:
        with open('root.crt') as r:
            f.write(r.read())
        with open('other_root.crt') as r:
            f.write(r.read())

    # start ghostunnel with --allow-all
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-all',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # client1 should be accepted
    pair1 = SocketPair(
            TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "client1 accepted")
    pair1.validate_can_send_from_server("toto", "client1 accepted")
    pair1.cleanup()

    # client2 (different OU/SAN) should also be accepted with --allow-all
    pair2 = SocketPair(
            TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair2.validate_can_send_from_client("toto", "client2 accepted (different OU)")
    pair2.validate_can_send_from_server("toto", "client2 accepted (different OU)")
    pair2.cleanup()

    # client signed by a different CA should still be rejected
    # use combined_ca so the TLS client trusts the server cert, but the
    # server won't trust the client cert (signed by other_root)
    assert_connection_rejected(
        TlsClient('untrusted_client', 'combined_ca', LISTEN_PORT), TcpServer(TARGET_PORT),
        "untrusted_client")

    print_ok("OK")
finally:
    terminate(ghostunnel)
