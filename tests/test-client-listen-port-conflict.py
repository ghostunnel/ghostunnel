#!/usr/bin/env python3

"""
Test that ghostunnel client exits with an error when the listen port is already in use.
"""

from common import LOCALHOST, RootCert, print_ok, run_ghostunnel, terminate, TARGET_PORT, get_free_port
import socket

ghostunnel = None
blocking_socket = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # Occupy a port with a blocking socket
    conflict_port = get_free_port(release=True)
    blocking_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    blocking_socket.bind((LOCALHOST, conflict_port))
    blocking_socket.listen(1)

    # start ghostunnel client, which should fail because port is already taken
    ghostunnel = run_ghostunnel(['client',
                                 '--listen={0}:{1}'.format(LOCALHOST, conflict_port),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=client.p12',
                                 '--cacert=root.crt'])

    # wait for ghostunnel to exit and make sure error code is not zero
    ret = ghostunnel.wait(timeout=10)
    if ret == 0:
        raise Exception(
            'ghostunnel terminated with zero, but expected error due to port conflict')
    else:
        print_ok("OK (terminated with non-zero exit as expected)")
finally:
    terminate(ghostunnel)
    if blocking_socket:
        blocking_socket.close()
