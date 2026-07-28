#!/usr/bin/env python3

"""
Test that TLS session resumption does not bypass access control.

Two properties are covered:

  1. A successful reload drops outstanding session tickets, so a client that
     would otherwise resume falls back to a full handshake and picks up the
     reloaded certificate and trust store.

  2. When a reload leaves the TLS configuration in place -- here because the
     CA bundle on disk is broken, so that half of the reload fails -- but the
     OPA policy did change, a client that resumes its session is still checked
     against the new policy. crypto/tls skips the VerifyPeerCertificate
     callback on resumed connections, so ghostunnel enforces access control
     from VerifyConnection, which Go runs on every handshake.
"""

from common import LOCALHOST, LISTEN_PORT, TARGET_PORT, STATUS_PORT, TIMEOUT, \
    MySocket, RootCert, SocketPair, TcpServer, assert_connection_rejected, \
    print_ok, reload_args, run_ghostunnel, status_info, terminate, \
    trigger_reload, wait_for_status

from tempfile import mkdtemp
import io
import json
import os
import shutil
import socket
import ssl
import tarfile

ALLOW_POLICY = """package policy

import input

default allow := false

allow if {
	input.certificate.DNSNames[_] == "client1"
}
"""

DENY_POLICY = """package policy

import input

default allow := false
"""


def write_bundle(path, rego):
    """Write an OPA bundle containing a single policy module."""
    def add(tar, name, content):
        info = tarfile.TarInfo(name)
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))

    with tarfile.open(path, 'w:gz') as tar:
        add(tar, '/.manifest', json.dumps(
            {"revision": "", "roots": [""], "rego_version": 1}).encode())
        add(tar, '/data.json', b'{}')
        add(tar, '/policy/policy.rego', rego.encode())


class ResumableTlsClient(MySocket):
    """TLS client that can save a session ticket and replay it on a later
    connection, so the server sees a resumed handshake."""

    def __init__(self, ctx, session=None):
        super().__init__()
        self.ctx = ctx
        self.session = session
        self.session_reused = None

    def connect(self, attempts=1, peer=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        self.socket = self.ctx.wrap_socket(
            sock, server_hostname=LOCALHOST, session=self.session)
        self.socket.connect((LOCALHOST, LISTEN_PORT))
        self.session_reused = self.socket.session_reused
        self.session = self.socket.session


def new_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    # A copy of the CA, so the client keeps working after the server's copy is
    # deliberately corrupted below.
    ctx.load_verify_locations(cafile='root_good.crt')
    ctx.load_cert_chain('client1.crt', 'client1.key')
    # Pin to TLS 1.2: the session ticket then arrives during the handshake and
    # is available immediately. Under TLS 1.3 it is sent afterwards, which
    # would make capturing it depend on reading from the connection first.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def reload(ghostunnel):
    pre_reload = status_info().get('last_reload')
    trigger_reload(ghostunnel)
    wait_for_status(lambda info: info.get('last_reload') != pre_reload, timeout=10)


def connect(ctx, session, msg):
    """Connect (optionally resuming session) and exchange a byte."""
    client = ResumableTlsClient(ctx, session)
    pair = SocketPair(client, TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client('hello', msg)
    pair.cleanup()
    return client


ghostunnel = None
tmp_dir = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert(
        'server',
        san='DNS:server,IP:127.0.0.1,IP:::1,DNS:localhost')
    root.create_signed_cert(
        'client1',
        san='DNS:client1,IP:127.0.0.1,IP:::1,DNS:localhost')
    shutil.copyfile('root.crt', 'root_good.crt')

    tmp_dir = mkdtemp()
    bundle = os.path.join(tmp_dir, 'bundle.tar.gz')
    write_bundle(bundle, ALLOW_POLICY)

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-policy=' + bundle,
                                 '--allow-query=data.policy.allow',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args())

    ctx = new_context()

    # first connection: full handshake, and capture the session ticket
    client = connect(ctx, None, 'initial connection works')
    if client.session is None:
        raise Exception('server did not issue a session ticket')
    print_ok('server issued a session ticket')

    # the ticket must actually be accepted, otherwise the rest of this test
    # would prove nothing
    client = connect(ctx, client.session, 'resumed connection works')
    if not client.session_reused:
        raise Exception('session was not resumed')
    print_ok('session resumed')

    # (1) a successful reload drops the session, so clients re-handshake
    # against the reloaded configuration
    reload(ghostunnel)
    client = connect(ctx, client.session, 'connection works after reload')
    if client.session_reused:
        raise Exception('session survived a reload, expected it to be dropped')
    print_ok('reload drops outstanding sessions')

    # (2) break the CA bundle so the certificate/trust-store half of a reload
    # fails and leaves the TLS configuration -- and its session tickets -- in
    # place, while the policy still reloads
    with open('root.crt', 'wb') as f:
        f.write(b'this is not a pem file at all, garbage bytes\n')

    reload(ghostunnel)
    client = connect(ctx, client.session, 'connection works after failed reload')
    if not client.session_reused:
        raise Exception('session did not survive a failed TLS reload')
    session = client.session
    print_ok('session survives a reload that left the TLS config in place')

    # now revoke access. The TLS config still cannot reload, so the client's
    # ticket stays valid and the server sees a resumed handshake -- which must
    # be checked against the new policy.
    write_bundle(bundle, DENY_POLICY)
    reload(ghostunnel)

    assert_connection_rejected(
        ResumableTlsClient(ctx, session), TcpServer(TARGET_PORT),
        'resumed connection under revoked policy')

    # baseline: a full handshake is rejected under the same policy
    assert_connection_rejected(
        ResumableTlsClient(ctx), TcpServer(TARGET_PORT),
        'new connection under revoked policy')

    print_ok('OK')
finally:
    terminate(ghostunnel)
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)
