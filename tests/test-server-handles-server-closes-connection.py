#!/usr/bin/env python3

"""
Ensures when server disconnects that the client connection also disconnects.
"""

from common import SocketPair, TcpServer, TlsClient, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_server

if __name__ == "__main__":
    ghostunnel = None
    try:
        root = create_default_certs()
        ghostunnel = start_ghostunnel_server(extra_args=['--close-timeout=10s'])

        # connect with client, confirm that the tunnel is up
        pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_server(
            "hello world", "1: server -> client")
        pair.validate_can_send_from_client(
            "hello world", "1: client -> server")
        pair.validate_closing_server_closes_client(
            "1: server closed -> client closed")

        pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
        pair.validate_can_send_from_server(
            "hello world", "2: server -> client")
        pair.validate_can_send_from_client(
            "hello world", "2: client -> server")
        pair.validate_half_closing_server_closes_client(
            "2: server closed -> client closed")

        print_ok("OK")
    finally:
        terminate(ghostunnel)
