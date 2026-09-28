#!/usr/bin/env python3

"""
Test that a reload invalidates outstanding TLS sessions.

A client that resumes a TLS session skips the full handshake, and with it the
access control check (crypto/tls does not call VerifyPeerCertificate on a
resumed connection). Ghostunnel bounds that by tying session invalidation to
reloads: every reload drops outstanding sessions, so every client's next
connection is a full handshake against the reloaded certificate, trust store
and policy.

Covered here, for each of TLS 1.2 and TLS 1.3:

  1. Resumption works at all, so the rest of the test proves something.
  2. A reload drops the session; the client's next connection is a full
     handshake.
  3. A policy change followed by a reload therefore takes effect for a client
     that was holding a session ticket.

The companion test-server-session-resumption-ca-failure.py covers a reload
where the TLS configuration fails to load while the policy reloads.
"""

from common import IS_WINDOWS, LOCALHOST, LISTEN_PORT, TARGET_PORT, \
    STATUS_PORT, ResumableTlsClient, RootCert, SocketPair, TcpServer, \
    assert_connection_rejected, print_ok, reload_and_wait, \
    resumable_client_context, reload_args, run_ghostunnel, terminate, \
    write_opa_bundle

from tempfile import mkdtemp
import os
import shutil
import ssl

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


def connect(ctx, session, msg):
    """Connect (optionally resuming session), exchange data in both
    directions, and capture the session for a later connection.

    Data has to flow from the backend to the client too: under TLS 1.3 the
    session ticket is sent after the handshake, so the client only picks it up
    once it reads from the connection."""
    client = ResumableTlsClient(ctx, session)
    pair = SocketPair(client, TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client('ping', msg)
    pair.validate_can_send_from_server('pong', '{0} (backend to client)'.format(msg))
    client.save_session()
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

    tmp_dir = mkdtemp()
    bundle = os.path.join(tmp_dir, 'bundle.tar.gz')
    write_opa_bundle(bundle, ALLOW_POLICY)

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

    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        label = version.name
        ctx = resumable_client_context('client1', 'root', version)

        # (1) first connection: full handshake, and capture the session
        client = connect(ctx, None, '{0}: initial connection works'.format(label))
        if client.session is None:
            raise Exception('server did not issue a session ticket')
        print_ok('{0}: server issued a session ticket'.format(label))

        # the session must actually be accepted, otherwise the rest of this test
        # would prove nothing
        client = connect(ctx, client.session,
                         '{0}: resumed connection works'.format(label))
        if client.session_reused:
            print_ok('{0}: session resumed'.format(label))
        elif IS_WINDOWS:
            # On Windows the only way to trigger a reload is --timed-reload=1s,
            # so a reload may land between these two connections and drop the
            # session legitimately. The invalidation checks below still hold.
            print_ok('{0}: session not resumed, a timed reload likely '
                     'intervened'.format(label))
        else:
            raise Exception('session was not resumed')

        # (2) a reload drops the session, so clients re-handshake against the
        # reloaded configuration
        reload_and_wait(ghostunnel)
        client = connect(ctx, client.session,
                         '{0}: connection works after reload'.format(label))
        if client.session_reused:
            raise Exception('session survived a reload, expected it to be dropped')
        print_ok('{0}: reload drops outstanding sessions'.format(label))

        # (3) revoke access through a policy reload. The client still holds a
        # session from before the reload; it must not get in with it.
        session = client.session
        write_opa_bundle(bundle, DENY_POLICY)
        reload_and_wait(ghostunnel)

        assert_connection_rejected(
            ResumableTlsClient(ctx, session), TcpServer(TARGET_PORT),
            '{0}: connection with old session under revoked policy'.format(label))

        # baseline: a fresh connection is rejected under the same policy
        assert_connection_rejected(
            ResumableTlsClient(ctx), TcpServer(TARGET_PORT),
            '{0}: new connection under revoked policy'.format(label))

        # restore access for the next round
        write_opa_bundle(bundle, ALLOW_POLICY)
        reload_and_wait(ghostunnel)

    print_ok('OK')
finally:
    terminate(ghostunnel)
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)
