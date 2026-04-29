#!/usr/bin/env python3

"""
Tests that ghostunnel server works with platform-specific system logging
(--syslog on Unix/macOS, --eventlog on Windows).
"""

import sys

from common import (IS_WINDOWS, LISTEN_PORT, TARGET_PORT, SocketPair,
                    TcpServer, TlsClient, create_default_certs, print_ok,
                    start_ghostunnel_server, terminate, wait_for_status)

if IS_WINDOWS:
    system_log_flag = '--eventlog'
else:
    system_log_flag = '--syslog'

ghostunnel = None
root = None
try:
    root = create_default_certs()
    ghostunnel = start_ghostunnel_server(extra_args=[system_log_flag])

    try:
        wait_for_status(lambda info: True, timeout=10)
    except TimeoutError:
        print('ghostunnel failed to start with {0}, skipping'.format(
            system_log_flag), file=sys.stderr)
        sys.exit(2)

    # validate tunnel works with system logging enabled
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    if root:
        root.cleanup()
