#!/usr/bin/env python3

"""
Tests that ghostunnel server mode works with a macOS keychain identity
loaded via --keychain-identity flag. Creates a temporary keychain,
imports a test identity into it via the security CLI, and cleans up
after the test.
"""

import os
import subprocess
from common import (LOCALHOST, LISTEN_PORT, RootCert, STATUS_PORT,
                    SocketPair, TARGET_PORT, TcpServer, TlsClient, print_ok,
                    run_ghostunnel, require_platform, terminate)

KEYCHAIN_PASSWORD = 'keychain-test-password'
KEYCHAIN_PATH = os.path.join(os.getcwd(), 'ghostunnel-test.keychain')
P12_PASSWORD = 'testpass'

# Save original keychain search list so we can restore it.
_original_keychains = None


def _parse_keychain_paths(output):
    """Parse output of `security list-keychains` into a list of paths."""
    paths = []
    for line in output.strip().splitlines():
        kc = line.strip().strip('"')
        if kc:
            paths.append(kc)
    return paths


def setup_temp_keychain(p12_path, p12_password):
    """Create a temporary keychain, import a PKCS#12 identity, and add
    the keychain to the search list so SecItemCopyMatching can find it."""
    global _original_keychains

    # Save original search list
    out = subprocess.check_output(
        ['security', 'list-keychains', '-d', 'user'],
        text=True)
    _original_keychains = _parse_keychain_paths(out)

    # Create temporary keychain
    subprocess.check_call(
        ['security', 'create-keychain', '-p', KEYCHAIN_PASSWORD, KEYCHAIN_PATH])

    # Disable auto-lock
    subprocess.check_call(
        ['security', 'set-keychain-settings', KEYCHAIN_PATH])

    # Unlock
    subprocess.check_call(
        ['security', 'unlock-keychain', '-p', KEYCHAIN_PASSWORD, KEYCHAIN_PATH])

    # Import PKCS#12 identity (-A allows all applications to access)
    subprocess.check_call(
        ['security', 'import', p12_path, '-k', KEYCHAIN_PATH,
         '-f', 'pkcs12', '-P', p12_password, '-A'])

    # Prepend temp keychain to user search list
    subprocess.check_call(
        ['security', 'list-keychains', '-d', 'user', '-s', KEYCHAIN_PATH]
        + _original_keychains)


def cleanup_temp_keychain():
    """Restore original keychain search list and delete temp keychain."""
    try:
        if _original_keychains is not None:
            subprocess.call(
                ['security', 'list-keychains', '-d', 'user', '-s']
                + _original_keychains)
        subprocess.call(['security', 'delete-keychain', KEYCHAIN_PATH])
    except Exception as e:
        print("warning: keychain cleanup failed: {}".format(e))


require_platform('Darwin')

ghostunnel = None
try:
    # Create certs
    root = RootCert('root')
    root.create_signed_cert('server', p12_password=P12_PASSWORD)
    root.create_signed_cert('client', p12_password=None)

    # Set up temporary keychain with server identity
    setup_temp_keychain(os.path.abspath('server.p12'), P12_PASSWORD)

    # Start ghostunnel with keychain identity
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keychain-identity=server',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # Validate the tunnel works
    pair = SocketPair(
        TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("hello", "client -> server")
    pair.validate_can_send_from_server("world", "server -> client")
    pair.validate_tunnel_ou("server", "ou=server")
    pair.validate_closing_client_closes_server("client close -> server close")

    print_ok("OK")
finally:
    terminate(ghostunnel)
    cleanup_temp_keychain()
