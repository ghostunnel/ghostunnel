#!/usr/bin/env python3

"""
Server-mode TLS termination on a unix-domain listener (--listen=unix:PATH).
Two phases:
  1. Plain TLS-over-unix: handshake + bidirectional payload to a TCP backend.
  2. With --proxy-protocol: pins down current behavior. The non-TCP fallback
     in proxy.go transportProtocol claims TCPv4 while SourceAddr is a
     UnixAddr, so proxyproto fails to format the header and the backend
     sees EOF before any bytes. A future fix that emits a proper header
     (AF_UNIX/AF_UNSPEC) or rejects at startup will flip the assertion.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, \
                   print_ok, run_ghostunnel, require_platform, terminate, \
                   TARGET_PORT, TIMEOUT
from tempfile import mkdtemp
import os
import os.path
import shutil
import socket
import ssl

require_platform('Darwin', 'Linux', 'BSD')

# PROXY protocol v2 signature (12 bytes)
PP2_SIGNATURE = b'\r\n\r\n\x00\r\nQUIT\n'

_SO_REUSEPORT = getattr(socket, 'SO_REUSEPORT', None)


def _connect_tls_over_unix(socket_path, ca_cert, cert_chain, key_file):
    """Open an AF_UNIX socket and complete a TLS handshake on it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.load_cert_chain(cert_chain, key_file)
    # unix peer name won't match a DNS/IP SAN; skip hostname check.
    ctx.check_hostname = False

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(TIMEOUT)
    # connect first, then wrap (so failures in connect/wrap are clearly
    # attributable in tracebacks).
    sock.connect(socket_path)
    return ctx.wrap_socket(sock, server_hostname=LOCALHOST)


def _run_plain_phase():
    """TLS-over-unix listener forwards to a TCP backend (no PROXY)."""
    print_ok("=== phase: plain unix listener ===")

    tmpdir = mkdtemp(prefix='ghostunnel-unix-listener-')
    sock_path = os.path.join(tmpdir, 'listener.sock')

    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if _SO_REUSEPORT is not None:
        backend.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
    backend.settimeout(TIMEOUT)
    backend.bind((LOCALHOST, TARGET_PORT))
    backend.listen(1)

    handle = run_ghostunnel(['server',
                             '--listen=unix:{0}'.format(sock_path),
                             '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                             '--keystore=server.p12',
                             '--cacert=root.crt',
                             '--allow-ou=client',
                             '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])
    try:
        TcpClient(STATUS_PORT).connect(20)

        # Sanity-check the unix listener path was created (if not,
        # listening on unix: silently failed and we want clear failure).
        if not os.path.exists(sock_path):
            raise Exception(
                "ghostunnel did not create unix listener at {0}".format(
                    sock_path))
        print_ok("unix listener created at {0}".format(sock_path))

        tls = _connect_tls_over_unix(
            sock_path, 'root.crt', 'client.crt', 'client.key')
        print_ok("TLS handshake over unix socket succeeded")

        conn, _ = backend.accept()
        conn.settimeout(TIMEOUT)

        # Bidirectional payload — proves TLS-over-unix actually
        # terminates and forwards in both directions.
        tls.send(b'hello unix')
        data = b''
        while len(data) < len(b'hello unix'):
            chunk = conn.recv(len(b'hello unix') - len(data))
            if not chunk:
                raise Exception("backend closed before payload received")
            data += chunk
        if data != b'hello unix':
            raise Exception(
                "client->server payload mismatch: {0!r}".format(data))
        print_ok("client->server payload forwarded")

        conn.send(b'hi back')
        recv = b''
        while len(recv) < len(b'hi back'):
            chunk = tls.recv(len(b'hi back') - len(recv))
            if not chunk:
                raise Exception("tunnel closed before reply received")
            recv += chunk
        if recv != b'hi back':
            raise Exception(
                "server->client payload mismatch: {0!r}".format(recv))
        print_ok("server->client payload forwarded")

        tls.close()
        conn.close()
    finally:
        terminate(handle)
        backend.close()
        if os.path.exists(sock_path):
            try:
                os.remove(sock_path)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


def _run_proxy_protocol_phase():
    """TLS-over-unix listener with --proxy-protocol. Backend should see EOF
    before any PROXY header (current behavior: header-format failure)."""
    print_ok("=== phase: unix listener + --proxy-protocol ===")

    tmpdir = mkdtemp(prefix='ghostunnel-unix-listener-')
    sock_path = os.path.join(tmpdir, 'listener.sock')

    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if _SO_REUSEPORT is not None:
        backend.setsockopt(socket.SOL_SOCKET, _SO_REUSEPORT, 1)
    backend.settimeout(TIMEOUT)
    backend.bind((LOCALHOST, TARGET_PORT))
    backend.listen(1)

    handle = run_ghostunnel(['server',
                             '--listen=unix:{0}'.format(sock_path),
                             '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                             '--keystore=server.p12',
                             '--cacert=root.crt',
                             '--allow-ou=client',
                             '--proxy-protocol',
                             '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])
    try:
        TcpClient(STATUS_PORT).connect(20)

        if not os.path.exists(sock_path):
            raise Exception(
                "ghostunnel did not create unix listener at {0}".format(
                    sock_path))
        print_ok("unix listener created at {0}".format(sock_path))

        tls = _connect_tls_over_unix(
            sock_path, 'root.crt', 'client.crt', 'client.key')
        print_ok("TLS handshake over unix socket succeeded")

        conn, _ = backend.accept()
        conn.settimeout(TIMEOUT)
        print_ok("backend accepted forwarded connection")

        # Read up to 16 bytes (a complete v2 header needs 16+). Expect EOF first.
        preamble = b''
        while len(preamble) < 16:
            try:
                chunk = conn.recv(16 - len(preamble))
            except (socket.timeout, TimeoutError):
                chunk = b''
            if not chunk:
                break
            preamble += chunk

        # If a future change emits a real PROXY v2 header for unix peers,
        # this fires and forces an explicit update to code and test.
        if preamble[:12] == PP2_SIGNATURE:
            fam = preamble[13] if len(preamble) > 13 else None
            raise Exception(
                "PROXY-protocol-over-unix now emits a v2 signature "
                "(family/proto byte = {0!r}); update this test and "
                "decide whether the new contract is correct.".format(fam))

        if len(preamble) != 0:
            raise Exception(
                "expected backend to see EOF before any bytes when "
                "--proxy-protocol is combined with a unix listener "
                "(header-format failure), got {0} bytes: {1!r}".format(
                    len(preamble), preamble))
        print_ok("backend saw EOF (current --proxy-protocol+unix "
                 "fallback closes the backend connection)")

        try:
            tls.close()
        except Exception:
            pass
        conn.close()
    finally:
        terminate(handle)
        backend.close()
        if os.path.exists(sock_path):
            try:
                os.remove(sock_path)
            except OSError:
                pass
        shutil.rmtree(tmpdir, ignore_errors=True)


root = RootCert('root')
root.create_signed_cert('server')
root.create_signed_cert('client')
try:
    _run_plain_phase()
    _run_proxy_protocol_phase()
finally:
    root.cleanup()

print_ok("OK")
