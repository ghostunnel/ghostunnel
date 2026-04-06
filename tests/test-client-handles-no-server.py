#!/usr/bin/env python3

"""
Ensures that client gets a timeout if there is no server.
"""

from common import SocketPair, TcpClient, TlsServer, print_ok, terminate, LISTEN_PORT, TARGET_PORT, create_default_certs, start_ghostunnel_client, get_free_port

ghostunnel = None
try:
    __root__ = create_default_certs()
    ghostunnel = start_ghostunnel_client()

    # client should fail to connect since nothing is listening on wrong_port
    wrong_port = get_free_port()
    try:
        _pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer(
            'server', 'root', wrong_port))
        raise Exception('client should have failed to connect')
    except TimeoutError:
        print_ok("timeout when nothing is listening on {0}".format(wrong_port))

    # client should connect
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.cleanup()
    print_ok("OK")
finally:
    terminate(ghostunnel)
