#!/usr/bin/env python3

"""
Tests that ghostunnel client mode works with --verify-spki-pin for SPKI pinning.
Verifies that a server with the correct pin is accepted and a server with
the wrong pin is rejected.
"""

from common import (
    LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient,
    TlsServer, print_ok, run_ghostunnel, terminate, assert_connection_rejected,
    LISTEN_PORT, TARGET_PORT, get_spki_pin,
)

ghostunnel = None
try:
    root = RootCert('root')
    root.create_signed_cert('client')

    server_cert = RootCert('server')

    server_pin = get_spki_pin('server.crt', 'sha256')
    print_ok("server SPKI pin: {0}".format(server_pin))

    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=client.crt',
                                 '--key=client.key',
                                 '--cacert=root.crt',
                                 '--verify-spki-pin={0}'.format(server_pin),
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Test 1: Server with matching pin should connect
    pair = SocketPair(
        TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> pin-matched server")
    pair.validate_can_send_from_server("world", "pin-matched server -> client")
    pair.validate_closing_client_closes_server("client close -> server close")
    print_ok("Test 1: Matching pin accepted OK")

    # Test 2: Server with wrong pin (different key) should be rejected
    other_root = RootCert('other_root')
    other_root.create_signed_cert('other_server')

    # Terminate and restart ghostunnel pointing at the wrong server
    terminate(ghostunnel)

    # The wrong-pin server has a different key, so its SPKI won't match
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=client.crt',
                                 '--key=client.key',
                                 '--cacert=root.crt',
                                 '--verify-spki-pin={0}'.format(server_pin),
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # The wrong-pin server MUST verify ghostunnel's client cert against 'root'
    # (the CA that signed client.crt), not 'other_root'. If it used 'other_root'
    # the server itself would reject ghostunnel's root-signed client cert during
    # the handshake, so the connection would fail even if ghostunnel's pin check
    # were broken (e.g. an always-accept regression) — masking the very thing
    # this test exists to catch. With 'root' here, a pin mismatch is the only
    # possible cause of rejection.
    assert_connection_rejected(
        TcpClient(LISTEN_PORT),
        TlsServer('other_server', 'root', TARGET_PORT),
        "wrong-pin server",
        timeout_ok=False,
    )
    print_ok("Test 2: Wrong pin rejected OK")

    print_ok("OK")
finally:
    terminate(ghostunnel)
