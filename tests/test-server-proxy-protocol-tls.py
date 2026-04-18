#!/usr/bin/env python3

"""
Tests that --proxy-protocol-mode=tls sends a PROXY protocol v2 header
with TLS metadata TLVs (SSL version, ALPN, SNI) but without client
certificate details.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, \
                   TlsClient, print_ok, run_ghostunnel, terminate, \
                   LISTEN_PORT, TARGET_PORT, TIMEOUT, parse_tlvs
import socket
import struct

# PROXY protocol v2 signature (12 bytes)
PP2_SIGNATURE = b'\r\n\r\n\x00\r\nQUIT\n'

# TLV type constants
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

    # start ghostunnel with --proxy-protocol-mode=tls
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--proxy-protocol-mode=tls',
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

    # read the PROXY protocol v2 header
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

    # read remaining payload
    fam_proto = header[13]
    payload_len = struct.unpack('!H', header[14:16])[0]
    payload = b''
    while len(payload) < payload_len:
        chunk = conn.recv(payload_len - len(payload))
        if not chunk:
            raise Exception("connection closed before payload received")
        payload += chunk

    # skip address data
    if fam_proto == 0x11:
        addr_size = 12
    elif fam_proto == 0x21:
        addr_size = 36
    else:
        addr_size = 0

    # parse TLVs
    tlv_data = payload[addr_size:]
    if len(tlv_data) == 0:
        raise Exception("no TLVs present in PROXY header (expected TLS metadata)")
    tlvs = parse_tlvs(tlv_data)
    tlv_dict = {t: v for t, v in tlvs}
    print_ok("parsed {0} TLV(s) from PROXY header".format(len(tlvs)))

    # verify PP2_TYPE_SSL is present
    if PP2_TYPE_SSL not in tlv_dict:
        raise Exception("PP2_TYPE_SSL not found in TLVs")

    ssl_value = tlv_dict[PP2_TYPE_SSL]
    if len(ssl_value) < 5:
        raise Exception("PP2_TYPE_SSL value too short")

    # Parse SSL sub-header flags
    ssl_flags = ssl_value[0]
    if not (ssl_flags & PP2_CLIENT_SSL):
        raise Exception("PP2_CLIENT_SSL flag not set")
    # In tls mode, cert flags should NOT be set even though a client cert was presented
    if ssl_flags & PP2_CLIENT_CERT_CONN:
        raise Exception("PP2_CLIENT_CERT_CONN should not be set in tls mode")
    print_ok("PP2_TYPE_SSL flags correct for tls mode: 0x{0:02x}".format(ssl_flags))

    # Parse SSL sub-TLVs
    ssl_sub_tlvs = parse_tlvs(ssl_value[5:])
    ssl_sub_dict = {t: v for t, v in ssl_sub_tlvs}

    # Should have version
    if PP2_SUBTYPE_SSL_VERSION not in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_VERSION not found")
    ssl_version = ssl_sub_dict[PP2_SUBTYPE_SSL_VERSION].decode('ascii')
    if 'TLS' not in ssl_version:
        raise Exception("unexpected SSL version: {0}".format(ssl_version))
    print_ok("SSL version: {0}".format(ssl_version))

    # Should NOT have client cert details
    if PP2_SUBTYPE_SSL_CN in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_CN should not be present in tls mode")
    if PP2_SUBTYPE_SSL_CLIENT_CERT in ssl_sub_dict:
        raise Exception("PP2_SUBTYPE_SSL_CLIENT_CERT should not be present in tls mode")
    print_ok("no client cert sub-TLVs present (tls mode correct)")

    # send application data and verify
    test_data = b'hello proxy protocol tls'
    client.get_socket().send(test_data)
    received = conn.recv(len(test_data))
    if received != test_data:
        raise Exception("application data mismatch")
    print_ok("application data passed through correctly")

    conn.close()
    backend.close()
    client.cleanup()

    print_ok("OK")
finally:
    terminate(ghostunnel)
