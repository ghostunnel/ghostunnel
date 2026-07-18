#!/usr/bin/env python3

"""
Tests that ghostunnel client mode works with --verify-spki-pin combined with
--disable-authentication, i.e. the DNS-over-TLS (DoT) style deployment where
ghostunnel presents no client certificate of its own and authenticates the
server by its SPKI pin alone.

The server uses cert_reqs=ssl.CERT_NONE so it does not ask for (or verify) a
client certificate; the only thing that can accept or reject the connection is
ghostunnel's pin check.
"""

import ssl

from common import (
    LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient,
    TlsServer, print_ok, run_ghostunnel, terminate, assert_connection_rejected,
    LISTEN_PORT, TARGET_PORT, get_spki_pin,
)

ghostunnel = None
try:
    # The server's own key/cert. No client cert is created: ghostunnel runs
    # with --disable-authentication and presents nothing to the server. The
    # RootCert handles must stay referenced for the lifetime of the test:
    # RootCert.__del__ deletes the generated .crt/.key files, so a bare
    # RootCert(...) would remove them again the moment it is garbage-collected.
    server = RootCert('server')

    server_pin = get_spki_pin('server.crt', 'sha256')
    print_ok("server SPKI pin: {0}".format(server_pin))

    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--disable-authentication',
                                 '--verify-spki-pin={0}'.format(server_pin),
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Test 1: Server with matching pin should connect, even though ghostunnel
    # presents no client certificate.
    pair = SocketPair(
        TcpClient(LISTEN_PORT),
        TlsServer('server', 'server', TARGET_PORT, cert_reqs=ssl.CERT_NONE))
    pair.validate_can_send_from_client("hello", "client -> pin-matched server")
    pair.validate_can_send_from_server("world", "pin-matched server -> client")
    pair.validate_closing_client_closes_server("client close -> server close")
    print_ok("Test 1: Matching pin accepted OK (no client cert)")

    # Test 2: Server with a different key (wrong pin) should be rejected. The
    # server still does not require a client cert, so the pin mismatch is the
    # only possible cause of rejection.
    other_server = RootCert('other_server')

    assert_connection_rejected(
        TcpClient(LISTEN_PORT),
        TlsServer('other_server', 'other_server', TARGET_PORT, cert_reqs=ssl.CERT_NONE),
        "wrong-pin server",
        timeout_ok=False,
    )
    print_ok("Test 2: Wrong pin rejected OK (no client cert)")

    print_ok("OK")
finally:
    terminate(ghostunnel)
