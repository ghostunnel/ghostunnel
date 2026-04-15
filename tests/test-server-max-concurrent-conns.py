#!/usr/bin/env python3

"""
Tests that --max-concurrent-conns limits the number of simultaneous connections.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TcpServer, \
                   TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
import socket
import ssl
import time

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel with --max-concurrent-conns=2
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--max-concurrent-conns=2',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # open first connection
    pair1 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("hello1", "pair1 works")
    print_ok("connection 1 established")

    # open second connection
    pair2 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair2.validate_can_send_from_client("hello2", "pair2 works")
    print_ok("connection 2 established")

    # third connection: the semaphore is full so ghostunnel won't even accept
    # the TCP connection. A TLS connect attempt should time out.
    blocked = False
    sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock3.settimeout(2)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cafile='root.crt')
        ctx.load_cert_chain('client.crt', 'client.key')
        tls_sock = ctx.wrap_socket(sock3, server_hostname=LOCALHOST)
        tls_sock.connect((LOCALHOST, LISTEN_PORT))
        # if we get here, connection was accepted — check if backend is reachable
        # (it shouldn't be since semaphore is full)
        backend3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend3.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        so_reuseport = getattr(socket, 'SO_REUSEPORT', None)
        if so_reuseport is not None:
            backend3.setsockopt(socket.SOL_SOCKET, so_reuseport, 1)
        backend3.settimeout(2)
        backend3.bind((LOCALHOST, TARGET_PORT))
        backend3.listen(1)
        try:
            backend3.accept()
            raise Exception("3rd connection should not have reached backend")
        except socket.timeout:
            blocked = True
        finally:
            backend3.close()
            tls_sock.close()
    except (socket.timeout, ssl.SSLError, ConnectionError, OSError):
        blocked = True
    finally:
        try:
            sock3.close()
        except Exception:
            pass

    if not blocked:
        raise Exception("3rd connection was not blocked by concurrency limit")
    print_ok("3rd connection correctly blocked by concurrency limit")

    # close first connection to free up a slot
    pair1.cleanup()
    print_ok("connection 1 closed")

    # give ghostunnel a moment to release the semaphore
    time.sleep(1)

    # now a new connection should succeed
    pair3 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair3.validate_can_send_from_client("hello3", "pair3 works after slot freed")
    print_ok("connection 3 established after freeing slot")

    pair2.cleanup()
    pair3.cleanup()

    print_ok("OK")
finally:
    terminate(ghostunnel)
