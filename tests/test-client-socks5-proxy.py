#!/usr/bin/env python3

# Verifies that ghostunnel's --proxy flag supports the socks5:// scheme.
# This exercises a completely different dialer in golang.org/x/net/proxy
# than the http:// CONNECT proxy (covered by test-client-via-http-connect-proxy.py),
# including the netproxy.ContextDialer type-assertion path in clientBackendDialer
# (main.go around line 962-976).
#
# The test runs an in-process minimal SOCKS5 server that:
#   1. negotiates no-auth (\x05\x01\x00 -> \x05\x00),
#   2. accepts a CONNECT request to a fake hostname,
#   3. dials 127.0.0.1 on the requested port,
#   4. splices bytes both ways until either side closes.
#
# We deliberately use an unresolvable hostname as the target so that ghostunnel
# must rely on the proxy for name resolution — proving the SOCKS5 dialer is
# actually carrying the target through to the proxy rather than resolving it
# locally.

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port
import socket
import struct
import threading
import select

FAKE_TARGET = "kQ8xZpL2Vf"  # unresolvable; only the proxy "knows" it

# CONNECT requests observed by the SOCKS5 server, captured for the assertion
# that exactly one CONNECT to the expected target was processed.
connect_log = []
connect_log_lock = threading.Lock()


def _splice(a, b):
    """Bidirectional byte splice between two connected sockets."""
    try:
        rlist = [a, b]
        for _ in range(1000):
            reads, _, errs = select.select(rlist, [], rlist, 10)
            if errs:
                break
            done = False
            for s in reads:
                try:
                    data = s.recv(8192)
                except Exception:
                    done = True
                    break
                if not data:
                    done = True
                    break
                (b if s is a else a).sendall(data)
            if done:
                break
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass  # best-effort
            try:
                s.close()
            except Exception:
                pass  # best-effort


def _serve_socks5_once(listener):
    """Handle exactly one SOCKS5 CONNECT, then close the listener."""
    try:
        client, _ = listener.accept()
    finally:
        try:
            listener.close()
        except Exception:
            pass  # best-effort

    try:
        # Method negotiation: VER=5, NMETHODS=1, METHODS=[0x00 (no auth)].
        greeting = client.recv(3)
        if len(greeting) < 3 or greeting[0] != 0x05:
            raise Exception("bad SOCKS5 greeting: {0!r}".format(greeting))
        client.sendall(b"\x05\x00")  # VER=5, METHOD=no auth

        # Request: VER CMD RSV ATYP DST.ADDR DST.PORT
        header = client.recv(4)
        if len(header) < 4 or header[0] != 0x05 or header[1] != 0x01:
            raise Exception("bad SOCKS5 request header: {0!r}".format(header))
        atyp = header[3]
        if atyp == 0x01:  # IPv4
            addr_bytes = client.recv(4)
            host = '.'.join(str(b) for b in addr_bytes)
        elif atyp == 0x03:  # FQDN
            ln = client.recv(1)[0]
            host = client.recv(ln).decode('ascii')
        elif atyp == 0x04:  # IPv6
            addr_bytes = client.recv(16)
            host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            raise Exception("unsupported ATYP {0}".format(atyp))
        port = struct.unpack('!H', client.recv(2))[0]

        with connect_log_lock:
            connect_log.append((host, port))
        print_ok("SOCKS5 CONNECT to {0}:{1}".format(host, port))

        # The fake hostname is not resolvable; dial loopback on the same port.
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(10)
        upstream.connect((LOCALHOST, port))

        # Success reply: VER=5, REP=0, RSV=0, ATYP=1, BND.ADDR=0.0.0.0, BND.PORT=0
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

        _splice(client, upstream)
    except Exception as e:
        print_ok("SOCKS5 handler error: {0}".format(e))
        try:
            client.close()
        except Exception:
            pass  # best-effort


ghostunnel = None
try:
    # Create certs. The server cert SAN lists the fake hostname so that
    # ghostunnel-client's TLS handshake validates against the target name
    # rather than the proxy address.
    root = RootCert('root')
    root.create_signed_cert('server', san='DNS:{0}'.format(FAKE_TARGET))
    root.create_signed_cert('client')

    # Allocate the SOCKS5 listener up front so we can pass its port to ghostunnel.
    proxy_port = get_free_port(release=True)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((LOCALHOST, proxy_port))
    listener.listen(1)
    listener.settimeout(30)

    proxy_thread = threading.Thread(target=_serve_socks5_once, args=(listener,))
    proxy_thread.daemon = True
    proxy_thread.start()

    # Start ghostunnel client pointing at the unresolvable target through the
    # socks5 proxy.
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(FAKE_TARGET, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--proxy=socks5://{0}:{1}'.format(LOCALHOST, proxy_port),
                                 '--connect-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # Drive a single connection through the tunnel. The backend TLS server
    # listens on TARGET_PORT (loopback); the SOCKS5 proxy will receive the
    # FQDN-typed CONNECT request and dial loopback there.
    pair = SocketPair(TcpClient(LISTEN_PORT), TlsServer('server', 'root', TARGET_PORT))
    pair.validate_can_send_from_client(
        'hello world', '1: client -> server (via socks5)')
    pair.validate_can_send_from_server(
        'hello world', '1: server -> client (via socks5)')
    pair.validate_closing_client_closes_server('closing client')
    pair.cleanup()

    # Wait for the proxy thread to finish so the connect_log is final.
    proxy_thread.join(timeout=10)

    # Assert that the SOCKS5 server saw exactly one CONNECT to the fake target.
    with connect_log_lock:
        observed = list(connect_log)
    if observed != [(FAKE_TARGET, TARGET_PORT)]:
        raise Exception(
            "expected exactly one SOCKS5 CONNECT to {0}:{1}, got {2!r}".format(
                FAKE_TARGET, TARGET_PORT, observed))
    print_ok("SOCKS5 proxy received exactly one CONNECT to {0}:{1}".format(
        FAKE_TARGET, TARGET_PORT))

    print_ok("OK")
finally:
    terminate(ghostunnel)
