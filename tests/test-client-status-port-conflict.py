#!/usr/bin/env python3

"""
Test that ghostunnel client exits with an error when the --status port is
already in use, and that the main listen port is released (not left bound
serving traffic without a health endpoint).
"""

from common import LOCALHOST, RootCert, print_ok, run_ghostunnel, terminate, TARGET_PORT, get_free_port
import socket

ghostunnel = None
blocking_socket = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # Occupy the STATUS port with a blocking socket
    status_conflict_port = get_free_port(release=True)
    blocking_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocking_socket.bind((LOCALHOST, status_conflict_port))
    blocking_socket.listen(1)

    # The main listen port should be free (and should be released by
    # ghostunnel when the status bind fails).
    listen_port = get_free_port(release=True)

    # start ghostunnel client; it should fail because the status port is taken
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, listen_port),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt',
                                 '--status={0}:{1}'.format(LOCALHOST, status_conflict_port)])

    # wait for ghostunnel to exit and make sure error code is not zero
    ret = ghostunnel.wait(timeout=10)
    if ret == 0:
        raise Exception(
            'ghostunnel terminated with zero, but expected error due to status port conflict')
    print_ok("OK (terminated with non-zero exit as expected)")

    # The main listen port should not be left bound by ghostunnel: a
    # connect attempt should fail (connection refused) since the process
    # exited and closed the listener.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(2)
    try:
        probe.connect((LOCALHOST, listen_port))
        raise Exception(
            'main listen port {0} is still accepting connections after status bind failure'.format(listen_port))
    except (ConnectionRefusedError, OSError) as e:
        print_ok("OK (main listen port released: {0})".format(e))
    finally:
        probe.close()
finally:
    terminate(ghostunnel)
    if blocking_socket:
        blocking_socket.close()
