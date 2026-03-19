#!/usr/bin/env python3

"""
Test that ghostunnel server exits with an error when the listen port is already in use.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT, get_free_port
import socket

if __name__ == "__main__":
    ghostunnel = None
    blocking_socket = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # Occupy a port with a blocking socket
        conflict_port = get_free_port()
        blocking_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocking_socket.bind((LOCALHOST, conflict_port))
        blocking_socket.listen(1)

        # start ghostunnel, which should fail because port is already taken
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:{1}'.format(LOCALHOST, conflict_port),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-ou=server'])

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
