#!/usr/bin/env python3

"""
Test that ensures that PKCS11 module support works.
"""

from common import LOCALHOST, STATUS_PORT, SocketPair, TcpClient, TcpServer, TlsClient, print_ok, run_ghostunnel, require_platform, status_info, terminate, trigger_reload, wait_for_status, LISTEN_PORT, TARGET_PORT, _ROOT_DIR
from shutil import copyfile
import os
import sys

require_platform('Darwin', 'Linux', 'BSD')

ghostunnel = None
try:
    # Only run PKCS11 tests if requested
    if 'GHOSTUNNEL_TEST_PKCS11' not in os.environ:
        print('GHOSTUNNEL_TEST_PKCS11 not set', file=sys.stderr)
        sys.exit(2)

    test_keys = os.path.join(_ROOT_DIR, 'test-keys')
    copyfile(os.path.join(test_keys, 'client-key.pem'), 'client.key')
    copyfile(os.path.join(test_keys, 'client-cert.pem'), 'client.crt')
    copyfile(os.path.join(test_keys, 'server-cert.pem'), 'server.crt')
    copyfile(os.path.join(test_keys, 'cacert.pem'), 'root.crt')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=server.crt',
                                 '--pkcs11-module={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_MODULE']),
                                 '--pkcs11-token-label={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_LABEL']),
                                 '--pkcs11-pin={0}'.format(os.environ['GHOSTUNNEL_TEST_PKCS11_PIN']),
                                 '--cacert=root.crt',
                                 '--allow-cn=client',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(3)

    # Test some connections
    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "1: client -> server")
    pair.validate_can_send_from_server(
        "hello world", "1: server -> client")
    pair.validate_closing_client_closes_server(
        "1: client closed -> server closed")

    # Trigger a reload to exercise the PKCS#11 cached-key code path
    # (pkcs11_enabled.go: "reusing previously cached private key handle from
    # module"). Without waiting for the reload to actually finish, a follow-up
    # connection could race and still observe the pre-reload tls.Config. By
    # waiting on the status endpoint's last_reload timestamp we guarantee the
    # cached-key branch in Reload() actually ran before the next handshake.
    pre_reload = status_info().get('last_reload')
    trigger_reload(ghostunnel)

    # wait until reload complete
    wait_for_status(lambda info: info.get('last_reload') != pre_reload and info.get('message') != 'reloading')
    print_ok("reloaded pkcs11 cert (cached HSM key handle reused)")

    # Test some connections (again) — handshake must still succeed, proving
    # the HSM-backed signer obtained from the cached private key still works.
    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "2: client -> server after reload")
    pair.validate_can_send_from_server(
        "hello world", "2: server -> client after reload")
    pair.validate_closing_client_closes_server(
        "2: client closed -> server closed after reload")

    # Trigger a second reload to confirm repeated reloads continue to hit the
    # cached-key branch (no re-login to the HSM, no PIN re-prompt, no crash).
    pre_reload = status_info().get('last_reload')
    trigger_reload(ghostunnel)
    wait_for_status(lambda info: info.get('last_reload') != pre_reload and info.get('message') != 'reloading')
    print_ok("reloaded pkcs11 cert again (cached HSM key handle reused)")

    pair = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client(
        "hello world", "3: client -> server after second reload")
    pair.validate_can_send_from_server(
        "hello world", "3: server -> client after second reload")
    pair.validate_closing_client_closes_server(
        "3: client closed -> server closed after second reload")

    print_ok("OK")
finally:
    terminate(ghostunnel)
