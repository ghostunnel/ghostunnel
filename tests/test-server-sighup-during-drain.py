#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpServer, TlsClient, print_ok, run_ghostunnel, require_platform, terminate, LISTEN_PORT, TARGET_PORT
import signal
import time

require_platform('Darwin', 'Linux', 'BSD')

ghostunnel = None
try:
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--shutdown-timeout=30s',
                                 '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT)])

    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # in-flight connection keeps the proxy in its p.Wait() drain window
    pair1 = SocketPair(TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client("toto", "pair1 works")

    print_ok('triggering graceful shutdown via SIGTERM (connection still open)')
    ghostunnel.terminate()
    time.sleep(1)

    if ghostunnel.poll() is not None:
        raise Exception('ghostunnel exited before we could send SIGHUP (rc={0})'.format(ghostunnel.returncode))

    print_ok('sending SIGHUP mid-drain')
    ghostunnel.send_signal(signal.SIGHUP)
    time.sleep(1)

    pair1.cleanup()

    stopped = False
    for _ in range(30):
        if ghostunnel.poll() is not None:
            stopped = True
            break
        print_ok("ghostunnel is still alive")
        time.sleep(1)

    if not stopped:
        raise Exception('ghostunnel did not terminate within 30 seconds')

    if ghostunnel.returncode < 0:
        raise Exception('ghostunnel was killed by signal {0} during drain (SIGHUP not ignored) instead of exiting cleanly'.format(-ghostunnel.returncode))
    if ghostunnel.returncode != 0:
        raise Exception('ghostunnel exited non-zero ({0}) instead of clean drain'.format(ghostunnel.returncode))

    print_ok("OK (drained cleanly despite mid-drain SIGHUP)")
finally:
    terminate(ghostunnel)
