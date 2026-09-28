#!/usr/bin/env python3

"""
Test that a *failed* reload still invalidates outstanding TLS sessions.

Companion to test-server-session-resumption.py, which covers the successful
reload. Here the CA bundle on disk is replaced with garbage before the reload,
so reloading the TLS configuration fails while the OPA policy reloads fine.

A client that resumes a TLS session skips the full handshake, and with it the
access control check (crypto/tls does not call VerifyPeerCertificate on a
resumed connection). If invalidation depended on the TLS source successfully
swapping in new configuration, a failed reload would leave old tickets valid
and a client holding one could keep using the access decision it was granted
under the previous policy. Session invalidation is therefore tied to the
reload itself, not to its outcome.

Steps, for each of TLS 1.2 and TLS 1.3:

  1. Connect under a policy that allows the client, and resume, so the rest of
     the test proves something.
  2. Corrupt the CA bundle and revoke access in the policy, then reload. The
     TLS reload fails (and says so in the log); the policy reload succeeds.
  3. The client's saved session must no longer be accepted, and the resulting
     full handshake must be denied by the reloaded policy.
  4. Restore the CA bundle and the policy, reload, and check the tunnel
     recovers.
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

INVALID_CA = b"-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n"


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
log_file = None
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

    # ghostunnel reads the CA bundle from a copy we can break at will
    ca_bundle = os.path.join(tmp_dir, 'ca-bundle.pem')
    shutil.copyfile('root.crt', ca_bundle)

    log_path = os.path.join(tmp_dir, 'ghostunnel.log')
    log_file = open(log_path, 'wb')

    def log_contains(needle):
        log_file.flush()
        with open(log_path, 'rb') as f:
            return needle.encode() in f.read()

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=' + ca_bundle,
                                 '--allow-policy=' + bundle,
                                 '--allow-query=data.policy.allow',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args(),
                                stdout=log_file, stderr=log_file)

    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        label = version.name
        ctx = resumable_client_context('client1', 'root', version)

        # (1) a session is issued and actually resumes
        client = connect(ctx, None, '{0}: initial connection works'.format(label))
        if client.session is None:
            raise Exception('server did not issue a session ticket')

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

        # (2) break the CA bundle and revoke access, then reload. Reloading the
        # TLS configuration fails, so the trust store and certificate in use
        # are the ones from before; only the policy changes.
        session = client.session
        with open(ca_bundle, 'wb') as f:
            f.write(INVALID_CA)
        write_opa_bundle(bundle, DENY_POLICY)
        reload_and_wait(ghostunnel)

        if not log_contains('error reloading TLS configuration'):
            raise Exception('expected the TLS configuration reload to fail')
        print_ok('{0}: TLS configuration reload failed as intended'.format(label))

        # (3) the saved session must not get the client in. The ticket has to be
        # refused, and the full handshake that follows denied by the policy.
        assert_connection_rejected(
            ResumableTlsClient(ctx, session), TcpServer(TARGET_PORT),
            '{0}: connection with old session after failed reload'.format(label))

        # baseline: a client without a session is rejected under the same policy
        assert_connection_rejected(
            ResumableTlsClient(ctx), TcpServer(TARGET_PORT),
            '{0}: new connection under revoked policy'.format(label))

        # (4) put everything back and check the tunnel recovers
        shutil.copyfile('root.crt', ca_bundle)
        write_opa_bundle(bundle, ALLOW_POLICY)
        reload_and_wait(ghostunnel)

        connect(ctx, None, '{0}: connection works after recovery'.format(label))

    print_ok('OK')
finally:
    terminate(ghostunnel)
    if log_file:
        log_file.close()
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)
