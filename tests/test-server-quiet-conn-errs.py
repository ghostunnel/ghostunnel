#!/usr/bin/env python3

"""
Ensures that --quiet=conn-errs suppresses backend/copy connection error logs only,
while leaving TLS handshake-error logs intact.

We trigger a connection error by pointing ghostunnel at a TARGET_PORT where no
backend is listening: after a successful TLS handshake, ghostunnel fails to dial
the backend and would normally log "error on dial: ..." under LogConnectionErrors.

We also trigger a handshake error by connecting in plain TCP and verify that
"error on TLS handshake" still appears — only conn-errs are silenced.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, TlsClient, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT
import socket
import subprocess
import time

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel pointed at TARGET_PORT with NO backend bound.
    # After a successful handshake, the dial to the backend will fail
    # with connection refused, producing a LogConnectionErrors message.
    ghostunnel = run_ghostunnel(['server',
                                 '--quiet=conn-errs',
                                 '--connect-timeout=1s',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(20)

    # (1) Valid mTLS handshake, but no backend on TARGET_PORT -> "error on dial".
    # Do this a couple of times so the log line is more likely to appear if not silenced.
    for _ in range(2):
        client = TlsClient('client', 'root', LISTEN_PORT)
        try:
            client.connect()
            # Send some bytes; either the backend dial already failed (we'll see EOF)
            # or it fails as we try to fuse. Either way, ghostunnel emits the error.
            try:
                client.get_socket().send(b'ping')
                client.get_socket().recv(1)
            except Exception:
                pass
        except Exception as e:
            print('TLS connect path: {0}'.format(e))
        finally:
            client.cleanup()

    # (2) Plain TCP -> TLS listener: triggers a handshake error. This MUST still
    # appear in the logs because we are NOT silencing handshake-errs.
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.settimeout(5)
    plain.connect((LOCALHOST, LISTEN_PORT))
    try:
        plain.sendall(b'not a TLS ClientHello\n')
    except Exception:
        pass
    plain.close()

    # Give ghostunnel time to flush any (un)expected log lines.
    time.sleep(1)

    terminate(ghostunnel)
    out, err = ghostunnel.communicate()

    err_text = err.decode('utf-8', errors='replace')
    out_text = out.decode('utf-8', errors='replace')
    combined = err_text + out_text

    print('stdout (len={0}):'.format(len(out)))
    print(out_text)
    print('stderr (len={0}):'.format(len(err)))
    print(err_text)

    # Connection error logs should be suppressed.
    if 'error on dial' in combined:
        raise Exception('ghostunnel logged "error on dial" with --quiet=conn-errs')
    if 'error during copy' in combined:
        raise Exception('ghostunnel logged "error during copy" with --quiet=conn-errs')

    # Handshake errors should still be logged (we only silenced conn-errs).
    if 'error on TLS handshake' not in combined:
        raise Exception('expected "error on TLS handshake" log line (--quiet=conn-errs should not suppress LogHandshakeErrors)')

    print_ok('OK')
finally:
    terminate(ghostunnel)
