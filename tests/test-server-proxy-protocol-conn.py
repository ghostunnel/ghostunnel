#!/usr/bin/env python3

"""
Tests that bare --proxy-protocol sends a valid PROXY protocol v2 header
with connection info only (no TLVs) to the backend.
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

    # start ghostunnel with bare --proxy-protocol (conn mode, no TLVs)
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--proxy-protocol',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)])

    # set up backend listener manually
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

    # read the PROXY protocol v2 header (16 bytes minimum)
    header = b''
    while len(header) < 16:
        chunk = conn.recv(16 - len(header))
        if not chunk:
            raise Exception("connection closed before full header received")
        header += chunk

    # verify signature
    if header[:12] != PP2_SIGNATURE:
        raise Exception("invalid PROXY protocol v2 signature")
    print_ok("PROXY protocol v2 signature verified")

    # verify version and command
    ver_cmd = header[12]
    version = (ver_cmd & 0xF0) >> 4
    command = ver_cmd & 0x0F
    if version != 2 or command != 1:
        raise Exception("expected v2 PROXY, got v={0} cmd={1}".format(
            version, command))
    print_ok("version=2, command=PROXY verified")

    # verify address family
    fam_proto = header[13]
    if fam_proto not in (0x11, 0x21):
        raise Exception("unexpected family/protocol: 0x{0:02x}".format(fam_proto))
    print_ok("address family/protocol verified: 0x{0:02x}".format(fam_proto))

    # read remaining payload
    payload_len = struct.unpack('!H', header[14:16])[0]
    payload = b''
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            raise Exception("connection closed before payload received")
        payload += chunk

    # parse address data
    if fam_proto == 0x11:
        addr_size = 12
        src_addr = socket.inet_ntoa(payload[0:4])
        dst_addr = socket.inet_ntoa(payload[4:8])
        src_port = struct.unpack('!H', payload[8:10])[0]
        dst_port = struct.unpack('!H', payload[10:12])[0]
        print_ok("src={0}:{1} dst={2}:{3}".format(
            src_addr, src_port, dst_addr, dst_port))
        if src_addr != '127.0.0.1':
            raise Exception("expected source 127.0.0.1, got {0}".format(src_addr))
    elif fam_proto == 0x21:
        addr_size = 36
    else:
        addr_size = 0
    print_ok("PROXY protocol address data verified")

    # verify NO TLVs after address data (conn mode)
    tlv_data = payload[addr_size:]
    if len(tlv_data) != 0:
        raise Exception(
            "expected no TLVs in conn mode, but got {0} bytes".format(
                len(tlv_data)))
    print_ok("no TLVs present (conn mode correct)")

    # send application data and verify it passes through
    test_data = b'hello proxy protocol conn'
    client.get_socket().send(test_data)
    received = conn.recv(len(test_data))
    if received != test_data:
        raise Exception("application data mismatch")
    print_ok("application data passed through correctly after PROXY header")

    conn.close()
    backend.close()
    client.cleanup()

    print_ok("OK")
finally:
    terminate(ghostunnel)
