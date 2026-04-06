#!/usr/bin/env python3

"""
Ensures client1 can connect but that clients with ou=client2 or ca=other_root can't connect.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
import ssl

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client1')
    root.create_signed_cert('client2')

    other_root = RootCert('other_root')
    other_root.create_signed_cert('other_client1')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT),
                                 '--cacert=root.crt',
                                 '--disable-authentication'])

    # connect with no client cert, confirm that the tunnel is up
    pair = SocketPair(TlsClient(None, 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # connect with client1 cert, confirm that the tunnel is up
    pair2 = SocketPair(
        TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair2.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair2.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair2.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # connect with client2, confirm that the tunnel isn't up
    try:
        SocketPair(
            TlsClient('client2', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    except ssl.SSLError as err:
        raise Exception(
            'rejected unauthenticated client2, despite --disable-authentication') from err

    # connect with other_client1, confirm that the tunnel isn't up
    try:
        pair = SocketPair(
            TlsClient('other_client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    except ssl.SSLError as err:
        raise Exception(
            'rejected authenticated other_client1, despite --disable-authentication') from err

    pair.cleanup()
    print_ok("OK")
finally:
    terminate(ghostunnel)
