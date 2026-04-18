#!/usr/bin/env python3

"""
Tests that ghostunnel server mode works with a Windows certificate store
identity loaded via --keychain-identity flag. Imports a test PKCS#12
identity into the current user's "MY" store via certutil and cleans up
after the test.
"""

import os
import subprocess
from common import (LOCALHOST, LISTEN_PORT, RootCert, STATUS_PORT,
                    SocketPair, TARGET_PORT, TcpServer, TlsClient, print_ok,
                    run_ghostunnel, require_platform, terminate)

P12_PASSWORD = 'testpass'

# Use a name unlikely to collide with any pre-existing identity in the
# Windows certificate store.  The certstore code searches CurrentUser,
# CurrentService, and LocalMachine MY stores.
IDENTITY_NAME = 'ghostunnel-test-server'


def import_to_certstore(p12_path, p12_password):
    """Import a PKCS#12 identity into the current user's MY certificate store."""
    subprocess.check_call([
        'certutil', '-f', '-p', p12_password,
        '-user', '-importpfx', 'MY', p12_path
    ])


def cleanup_certstore(cn):
    """Remove certificates matching the given CN from the current user's
    MY store."""
    try:
        subprocess.call([
            'certutil', '-user', '-delstore', 'MY', cn
        ])
    except Exception as e:
        print("warning: certstore cleanup failed: {}".format(e))


require_platform('Windows')

ghostunnel = None
try:
    # Create certs
    root = RootCert('root')
    root.create_signed_cert(IDENTITY_NAME, p12_password=P12_PASSWORD)
    root.create_signed_cert('client', p12_password=None)

    # Import server identity into Windows cert store
    import_to_certstore(
        os.path.abspath('{0}.p12'.format(IDENTITY_NAME)), P12_PASSWORD)

    # Start ghostunnel with certstore identity
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keychain-identity={0}'.format(IDENTITY_NAME),
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Validate the tunnel works
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_tunnel_ou(IDENTITY_NAME, "ou=" + IDENTITY_NAME)
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    cleanup_certstore(IDENTITY_NAME)
