#!/usr/bin/env python3

"""
Test to check that --connect-timeout bounds slow OPA policy evaluation.

Loads a pathological Rego policy whose evaluation reliably takes much
longer than 1 second, starts ghostunnel with --connect-timeout 1s, and
verifies that:

  1. A client handshake is rejected within a couple of seconds (the
     OPAQueryTimeout context, plumbed through VerifyPeerCertificateServer,
     cancels the in-flight rego.Eval).
  2. The ghostunnel process remains alive and its /_status endpoint keeps
     responding while the pathological policy is loaded.
  3. After replacing the bundle with a fast allow-policy and sending
     SIGUSR1 to reload, new client connections succeed -- proving the
     listener recovered.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TcpServer, \
    TlsClient, print_ok, reload_args, run_ghostunnel, status_info, terminate, trigger_reload, wait_for_status, LISTEN_PORT, TARGET_PORT

from tempfile import mkdtemp
import shutil
import os
import socket
import ssl
import time

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert(
        'server',
        san='DNS:server,IP:127.0.0.1,IP:::1,DNS:localhost')
    root.create_signed_cert(
        'client1',
        san='DNS:client1,IP:127.0.0.1,IP:::1,DNS:localhost')

    # stage slow bundle in a tmpdir we can swap atomically on reload
    dir_path = os.path.dirname(os.path.realpath(__file__))
    tmp_dir = mkdtemp()
    shutil.copyfile(
        dir_path + '/test-server-opa-slow-policy.tar.gz',
        tmp_dir + '/bundle.tar.gz')

    # start ghostunnel with a tight 1s connect/OPA timeout
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-policy=' + tmp_dir + '/bundle.tar.gz',
                                 '--allow-query=data.policy.allow',
                                 '--connect-timeout=1s',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)]
                                + reload_args())

    # wait for the status port to come up
    TcpClient(STATUS_PORT).connect(20)
    # listening flag is set once the listener is up
    wait_for_status(lambda info: info.get('message') == 'listening')

    # The pathological rego rule iterates numbers.range(1, 5e7); a full
    # eval would take many seconds. With --connect-timeout=1s the OPA
    # query context is canceled and ghostunnel rejects the handshake.
    #
    # We do a raw TLS handshake (no backend SocketPair) so the only
    # latency we measure is the in-handshake OPA call. If OPAQueryTimeout
    # is not honored, the read below would block the full SOCKET_TIMEOUT
    # (set well above 1s) waiting for a handshake/data that never comes.
    SOCKET_TIMEOUT = 6.0
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile='root.crt')
    ctx.load_cert_chain('client1.crt', 'client1.key')
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(SOCKET_TIMEOUT)
    tls_sock = ctx.wrap_socket(raw, server_hostname=LOCALHOST)
    rejected_via = None
    rejection_start = time.time()
    try:
        tls_sock.connect((LOCALHOST, LISTEN_PORT))
        # Handshake "succeeded" on our side; ghostunnel may close after
        # OPA returns an error. Read until we observe EOF or an error.
        tls_sock.settimeout(SOCKET_TIMEOUT)
        data = tls_sock.recv(1)
        if data == b'':
            rejected_via = "clean close after handshake"
        else:
            raise Exception(
                "expected rejection but received {0!r} from server".format(data))
    except ssl.SSLError as e:
        rejected_via = "ssl.SSLError ({0})".format(e)
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        # Server forcibly closed the connection -- still a valid rejection.
        rejected_via = "{0} ({1})".format(type(e).__name__, e)
    finally:
        try:
            tls_sock.close()
        except Exception:
            # best-effort cleanup: socket may already be torn down by ghostunnel
            pass
    rejection_elapsed = time.time() - rejection_start
    if rejected_via is None:
        raise Exception("handshake unexpectedly succeeded (no rejection)")
    # 1s OPA timeout + handshake/IO overhead should be well under 5s.
    # If OPAQueryTimeout is not honored, the read will hit SOCKET_TIMEOUT
    # at 6s (or the slow eval will complete at ~12s) and elapsed > 5s.
    if rejection_elapsed > 5:
        raise Exception(
            "rejection took {0:.2f}s; expected <= 5s. "
            "OPAQueryTimeout did not bound rego.Eval".format(rejection_elapsed))
    print_ok("slow OPA policy rejection bounded by --connect-timeout: "
             "{0} in {1:.2f}s".format(rejected_via, rejection_elapsed))

    # The process must still be alive after the pathological eval was
    # canceled -- a hung goroutine or panic would break this.
    if ghostunnel.poll() is not None:
        raise Exception(
            "ghostunnel exited after slow-policy timeout "
            "(rc={0})".format(ghostunnel.returncode))

    # /_status must still respond and report the listener is up
    info = status_info()
    if info is None or info.get('message') != 'listening':
        raise Exception("status endpoint not responsive: {0}".format(info))
    print_ok("status endpoint still responsive under pathological policy")

    # Swap in a fast allow-all bundle and reload; new connections must succeed.
    shutil.copyfile(
        dir_path + '/test-allow-all-policy.tar.gz',
        tmp_dir + '/bundle.tar.gz')
    pre_reload = status_info().get('last_reload')
    trigger_reload(ghostunnel)

    # wait for the reload to be picked up
    wait_for_status(lambda info: info.get('last_reload') != pre_reload)
    print_ok("reloaded to fast allow-all policy")

    pair = SocketPair(
        TlsClient('client1', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair.validate_can_send_from_client("toto", "post-reload client send works")
    pair.validate_can_send_from_server("toto", "post-reload server send works")

    print_ok("OK")
finally:
    terminate(ghostunnel)
