#!/usr/bin/env python3

"""
Ensures that --quiet=handshake-errs suppresses TLS handshake error logs only,
while leaving normal connection logs (opening pipe / closed pipe) intact.

We trigger handshake failures by:
  1. Connecting via plain TCP and immediately closing (no TLS).
  2. Connecting via TLS with an untrusted client cert.

Either path produces a "error on TLS handshake" log line under LogHandshakeErrors;
with --quiet=handshake-errs none of those lines should appear, but a normal
mTLS connection should still log "opening pipe" / "closed pipe".
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, TlsClient, TcpServer, print_ok, run_ghostunnel, terminate, SocketPair, LISTEN_PORT, TARGET_PORT
import socket
import ssl
import subprocess
import time

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # untrusted CA + leaf, used to force a TLS handshake failure on the server.
    rogue = RootCert('rogue')
    rogue.create_signed_cert('rogue_client')

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server',
                                 '--quiet=handshake-errs',
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

    # (1) Plain TCP -> TLS listener: triggers a handshake error inside ghostunnel.
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.settimeout(5)
    plain.connect((LOCALHOST, LISTEN_PORT))
    # send a few bytes of garbage so the server actually starts the handshake
    try:
        plain.sendall(b'not a TLS ClientHello\n')
    except Exception:
        pass
    plain.close()

    # (2) TLS with an untrusted client cert: ghostunnel rejects during the handshake.
    rogue_client = TlsClient('rogue_client', 'root', LISTEN_PORT)
    try:
        rogue_client.connect()
    except ssl.SSLError:
        pass  # expected — server cannot verify our client cert
    except OSError:
        pass  # server may have closed the connection before TLS alert arrived
    finally:
        rogue_client.cleanup()

    # Give ghostunnel time to actually log (or not log) the handshake errors.
    time.sleep(1)

    # (3) Valid mTLS connection. The opening/closed pipe log lines for this
    # connection MUST still appear — only handshake errors are silenced.
    pair = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client('toto', 'works')
    pair.validate_can_send_from_server('toto', 'works')
    pair.cleanup()

    terminate(ghostunnel)
    out, err = ghostunnel.communicate()

    err_text = err.decode('utf-8', errors='replace')
    out_text = out.decode('utf-8', errors='replace')
    combined = err_text + out_text

    print('stdout (len={0}):'.format(len(out)))
    print(out_text)
    print('stderr (len={0}):'.format(len(err)))
    print(err_text)

    # Handshake error log should be suppressed.
    if 'error on TLS handshake' in combined:
        raise Exception('ghostunnel logged TLS handshake error with --quiet=handshake-errs')

    # But normal connection logs should still appear for valid connections.
    if 'opening pipe' not in combined:
        raise Exception('expected "opening pipe" log line for valid connection (--quiet=handshake-errs should not suppress LogConnections)')
    if 'closed pipe' not in combined:
        raise Exception('expected "closed pipe" log line for valid connection (--quiet=handshake-errs should not suppress LogConnections)')

    print_ok('OK')
finally:
    terminate(ghostunnel)
