#!/usr/bin/env python3

"""
Tests that --proxy-protocol-mode=tls-full sends a PROXY protocol v2 header
to the backend before forwarding application data, including TLS
metadata TLVs (SSL, ALPN, Authority, client cert).
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, \
                   TlsClient, print_ok, run_ghostunnel, terminate, \
                   LISTEN_PORT, TARGET_PORT, TIMEOUT, parse_tlvs
import socket
import struct

# PROXY protocol v2 signature (12 bytes)
PP2_SIGNATURE = b'\r\n\r\n\x00\r\nQUIT\n'

# TLV type constants
PP2_TYPE_ALPN = 0x01
PP2_TYPE_AUTHORITY = 0x02
PP2_TYPE_SSL = 0x20
PP2_SUBTYPE_SSL_VERSION = 0x21
PP2_SUBTYPE_SSL_CN = 0x22
PP2_SUBTYPE_SSL_CLIENT_CERT = 0x28

# SSL client flags
PP2_CLIENT_SSL = 0x01
PP2_CLIENT_CERT_CONN = 0x02
PP2_CLIENT_CERT_SESS = 0x04


ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel with --proxy-protocol-mode=tls-full (full TLS metadata + client cert)
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--proxy-protocol-mode=tls-full',
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
    ver_cmd = header[12]
    version = (ver_cmd & 0xF0) >> 4
    command = ver_cmd & 0x0F
    if version != 2:
        raise Exception("expected PROXY protocol version 2, got {0}".format(version))
    if command != 1:
        raise Exception("expected PROXY command, got {0}".format(command))
    print_ok("version=2, command=PROXY verified")

    # verify address family and protocol (byte 13)
    fam_proto = header[13]
    if fam_proto not in (0x11, 0x21):
        raise Exception("unexpected family/protocol: 0x{0:02x}".format(fam_proto))
    print_ok("address family/protocol verified: 0x{0:02x}".format(fam_proto))

    # read remaining payload (address data + TLVs)
    payload_len = struct.unpack('!H', header[14:16])[0]
    payload = b''
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            raise Exception("connection closed before payload received")
        payload += chunk

    # parse address data
    if fam_proto == 0x11:
        # IPv4: 4+4+2+2 = 12 bytes
        addr_size = 12
        if payload_len < addr_size:
            raise Exception("IPv4 address data too short: {0}".format(payload_len))
        src_addr = socket.inet_ntoa(payload[0:4])
        dst_addr = socket.inet_ntoa(payload[4:8])
        src_port = struct.unpack('!H', payload[8:10])[0]
        dst_port = struct.unpack('!H', payload[10:12])[0]
        print_ok("src={0}:{1} dst={2}:{3}".format(src_addr, src_port, dst_addr, dst_port))
        if src_addr != '127.0.0.1':
            raise Exception("expected source 127.0.0.1, got {0}".format(src_addr))
    elif fam_proto == 0x21:
        # IPv6: 16+16+2+2 = 36 bytes
        addr_size = 36
        if payload_len < addr_size:
            raise Exception("IPv6 address data too short: {0}".format(payload_len))
    else:
        addr_size = 0
    print_ok("PROXY protocol address data verified")

    # parse TLVs from remaining payload after address data
    tlv_data = payload[addr_size:]
    if len(tlv_data) == 0:
        raise Exception("no TLVs present in PROXY header")

    tlvs = parse_tlvs(tlv_data)
    tlv_dict = {t: v for t, v in tlvs}
    print_ok("parsed {0} TLV(s) from PROXY header".format(len(tlvs)))

    # --- Verify PP2_TYPE_SSL (0x20) ---
    if PP2_TYPE_SSL not in tlv_dict:
        raise Exception("PP2_TYPE_SSL (0x20) not found in TLVs")

    ssl_value = tlv_dict[PP2_TYPE_SSL]
    if len(ssl_value) < 5:
        raise Exception("PP2_TYPE_SSL value too short: {0} bytes".format(len(ssl_value)))

    # Parse 5-byte SSL sub-header
    ssl_flags = ssl_value[0]
    ssl_verify = struct.unpack('!I', ssl_value[1:5])[0]

    if not (ssl_flags & PP2_CLIENT_SSL):
        raise Exception("PP2_CLIENT_SSL flag not set")
    if not (ssl_flags & PP2_CLIENT_CERT_CONN):
        raise Exception("PP2_CLIENT_CERT_CONN flag not set (client cert was presented)")
    if ssl_verify != 0:
        raise Exception("expected verify=0 (success), got {0}".format(ssl_verify))
    print_ok("PP2_TYPE_SSL flags verified: flags=0x{0:02x}, verify={1}".format(
        ssl_flags, ssl_verify))

    # Parse nested SSL sub-TLVs
    ssl_sub_tlvs = parse_tlvs(ssl_value[5:])
    ssl_sub_dict = {t: v for t, v in ssl_sub_tlvs}
    print_ok("parsed {0} SSL sub-TLV(s)".format(len(ssl_sub_tlvs)))

    # Verify SSL_VERSION
    if PP2_SUBTYPE_SSL_VERSION not in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_VERSION not found")
    ssl_version = ssl_sub_dict[PP2_SUBTYPE_SSL_VERSION].decode('ascii')
    if 'TLS' not in ssl_version:
        raise Exception("unexpected SSL version: {0}".format(ssl_version))
    print_ok("SSL version: {0}".format(ssl_version))

    # Verify SSL_CN (client cert CN)
    if PP2_SUBTYPE_SSL_CN not in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_CN not found")
    ssl_cn = ssl_sub_dict[PP2_SUBTYPE_SSL_CN].decode('utf-8')
    if ssl_cn != 'client':
        raise Exception("expected CN='client', got '{0}'".format(ssl_cn))
    print_ok("SSL CN: {0}".format(ssl_cn))

    # Verify SSL_CLIENT_CERT (DER-encoded X.509)
    if PP2_SUBTYPE_SSL_CLIENT_CERT not in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_CLIENT_CERT not found")
    client_cert_der = ssl_sub_dict[PP2_SUBTYPE_SSL_CLIENT_CERT]
    if len(client_cert_der) == 0:
        raise Exception("client cert DER data is empty")
    # Basic DER validation: should start with SEQUENCE tag (0x30)
    if client_cert_der[0] != 0x30:
        raise Exception("client cert DER doesn't start with SEQUENCE tag")
    print_ok("SSL client cert: {0} bytes of DER data".format(len(client_cert_der)))

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
