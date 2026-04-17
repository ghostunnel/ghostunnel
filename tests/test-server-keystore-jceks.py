#!/usr/bin/env python3

"""
Tests that ghostunnel server mode works with a JCEKS keystore.
Requires keytool (from a JRE/JDK installation) and OpenSSL.

The test generates an RSA key pair and certificate using OpenSSL,
packages them into a PKCS#12 file, then converts to JCEKS format
using keytool -importkeystore.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, check_keytool, convert_p12_to_jceks, print_ok, run_ghostunnel, require_platform, terminate, LISTEN_PORT, TARGET_PORT

require_platform('Darwin', 'Linux', 'BSD')

ghostunnel = None
try:
    check_keytool()

    root = RootCert('root', algorithm='rsa')
    root.create_signed_cert('server', p12_password='changeit')
    root.create_signed_cert('client', p12_password=None)

    # convert PKCS#12 to JCEKS using keytool
    convert_p12_to_jceks('server', 'server', 'changeit')

    # start ghostunnel with JCEKS keystore
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.jceks',
                                 '--storepass=changeit',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # validate connection
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_tunnel_ou("server", "ou=server")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
