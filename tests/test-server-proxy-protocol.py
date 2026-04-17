#!/usr/bin/env python3

"""
Tests that --proxy-protocol sends a valid PROXY protocol v2 header
to the backend before forwarding application data.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, \
                   TlsClient, print_ok, run_ghostunnel, terminate, \
                   LISTEN_PORT, TARGET_PORT, TIMEOUT
import socket
import struct

# PROXY protocol v2 signature (12 bytes)
PP2_SIGNATURE = b'\r\n\r\n\x00\r\nQUIT\n'

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel with --proxy-protocol
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--proxy-protocol',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # set up backend listener manually (not via SocketPair, since we need
    # to read raw bytes before application data)
    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    so_reuseport = getattr(socket, 'SO_REUSEPORT', None)
    if so_reuseport is not None:
        backend.setsockopt(socket.SOL_SOCKET, so_reuseport, 1)
    backend.settimeout(TIMEOUT)
    backend.bind((LOCALHOST, TARGET_PORT))
    backend.listen(1)

    # wait for ghostunnel to start
    TcpClient(STATUS_PORT).connect(20)

    # connect a TLS client through the tunnel
    client = TlsClient('client', 'root', LISTEN_PORT)
    client.connect()

    # accept the backend connection
    conn, _ = backend.accept()
    conn.settimeout(TIMEOUT)

    # read the PROXY protocol v2 header
    # minimum header is 16 bytes: 12-byte signature + version/command + family + length
    header = b''
    while len(header) < 16:
        chunk = conn.recv(16 - len(header))
        if not chunk:
            raise Exception("connection closed before full header received")
        header += chunk

    # verify signature (first 12 bytes)
    signature = header[:12]
    if signature != PP2_SIGNATURE:
        raise Exception("invalid PROXY protocol v2 signature: {0}".format(
            signature.hex()))
    print_ok("PROXY protocol v2 signature verified")

    # verify version and command (byte 12)
    # version = high nibble (should be 0x2), command = low nibble (0x1 = PROXY)
    ver_cmd = header[12]
    version = (ver_cmd & 0xF0) >> 4
    command = ver_cmd & 0x0F
    if version != 2:
        raise Exception("expected PROXY protocol version 2, got {0}".format(version))
    if command != 1:
        raise Exception("expected PROXY command, got {0}".format(command))
    print_ok("version=2, command=PROXY verified")

    # verify address family and protocol (byte 13)
    # 0x11 = AF_INET + STREAM, 0x21 = AF_INET6 + STREAM
    fam_proto = header[13]
    if fam_proto not in (0x11, 0x21):
        raise Exception("unexpected family/protocol: 0x{0:02x}".format(fam_proto))
    print_ok("address family/protocol verified: 0x{0:02x}".format(fam_proto))

    # read address data (length is in bytes 14-15)
    addr_len = struct.unpack('!H', header[14:16])[0]
    addr_data = b''
    while len(addr_data) < addr_len:
        chunk = conn.recv(addr_len - len(addr_data))
        if not chunk:
            raise Exception("connection closed before address data received")
        addr_data += chunk

    if fam_proto == 0x11:
        # IPv4: 4+4+2+2 = 12 bytes (src_addr, dst_addr, src_port, dst_port)
        if addr_len < 12:
            raise Exception("IPv4 address data too short: {0}".format(addr_len))
        src_addr = socket.inet_ntoa(addr_data[0:4])
        dst_addr = socket.inet_ntoa(addr_data[4:8])
        src_port = struct.unpack('!H', addr_data[8:10])[0]
        dst_port = struct.unpack('!H', addr_data[10:12])[0]
        print_ok("src={0}:{1} dst={2}:{3}".format(src_addr, src_port, dst_addr, dst_port))
        if src_addr != '127.0.0.1':
            raise Exception("expected source 127.0.0.1, got {0}".format(src_addr))
    print_ok("PROXY protocol address data verified")

    # send application data through the tunnel and verify it arrives
    test_data = b'hello proxy protocol'
    client.get_socket().send(test_data)
    received = conn.recv(len(test_data))
    if received != test_data:
        raise Exception("application data mismatch: expected {0}, got {1}".format(
            test_data, received))
    print_ok("application data passed through correctly after PROXY header")

    # cleanup
    conn.close()
    backend.close()
    client.cleanup()

    print_ok("OK")
finally:
    terminate(ghostunnel)
