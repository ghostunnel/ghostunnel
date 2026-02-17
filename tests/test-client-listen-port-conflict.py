#!/usr/bin/env python3

"""
Test that ghostunnel client exits with an error when the listen port is already in use.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate
import socket

if __name__ == "__main__":
    ghostunnel = None
    blocking_socket = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')

        # Occupy port 13099 with a blocking socket
        blocking_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocking_socket.bind((LOCALHOST, 13099))
        blocking_socket.listen(1)

        # start ghostunnel client, which should fail because port is already taken
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13099'.format(LOCALHOST),
                                     '--target={0}:13100'.format(LOCALHOST),
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
