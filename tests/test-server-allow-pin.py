#!/usr/bin/env python3

"""
Tests that ghostunnel server mode works with --allow-pin for SPKI pinning.
Verifies that a client with the correct pin is accepted and a client with
the wrong pin is rejected. Also verifies that --allow-pin can be repeated so
that multiple keys (e.g. a current and a backup key) are accepted.
"""

from common import (
    LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer,
    TlsClient, print_ok, run_ghostunnel, terminate, assert_connection_rejected,
    LISTEN_PORT, TARGET_PORT, get_spki_pin,
)


ghostunnel = None
try:
    # Create two independent CAs with their own certs
    root = RootCert('root')
    root.create_signed_cert('server')

    client_cert = RootCert('client')

    bad_client = RootCert('bad_client')

    # Get the SPKI pin for the client cert
    client_pin = get_spki_pin('client.crt')
    print_ok("client SPKI pin: {0}".format(client_pin))

    # Start ghostunnel server with --allow-pin
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=server.crt',
                                 '--key=server.key',
                                 '--cacert=root.crt',
                                 '--allow-pin={0}'.format(client_pin),
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Test 1: Client with matching pin should connect
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "pin-matched client -> server")
    pair.validate_can_send_from_server("world", "server -> pin-matched client")
    pair.validate_closing_client_closes_server("client close -> server close")
    print_ok("Test 1: Matching pin accepted OK")

    assert_connection_rejected(
        TlsClient('bad_client', 'root', LISTEN_PORT),
        TcpServer(TARGET_PORT),
        "wrong-pin client",
    )
    print_ok("Test 2: Wrong pin rejected OK")

    # Test 3: --allow-pin repeated with two pins accepts a client matching
    # either pin (e.g. current + backup key during rotation).
    bad_client_pin = get_spki_pin('bad_client.crt')
    print_ok("bad_client SPKI pin: {0}".format(bad_client_pin))

    terminate(ghostunnel)
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=server.crt',
                                 '--key=server.key',
                                 '--cacert=root.crt',
                                 '--allow-pin={0}'.format(bad_client_pin),
                                 '--allow-pin={0}'.format(client_pin),
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # A client matching the second pin connects.
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "first-pin client -> server")
    print_ok("Test 3a: Client matching one of two pins accepted OK")

    # A client matching the first pin also connects.
    pair = SocketPair(
        TlsClient('bad_client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "second-pin client -> server")
    print_ok("Test 3b: Client matching other pin accepted OK")

    print_ok("OK")
finally:
    terminate(ghostunnel)
