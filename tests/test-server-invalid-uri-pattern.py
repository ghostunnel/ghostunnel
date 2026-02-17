#!/usr/bin/env python3

"""
Test that ghostunnel server exits with an error when given an invalid URI pattern.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # start ghostunnel with an empty/invalid --allow-uri pattern
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--cacert=root.crt',
                                     '--allow-uri='])

        # wait for ghostunnel to exit and make sure error code is not zero
        ret = ghostunnel.wait(timeout=10)
        if ret == 0:
            raise Exception(
                'ghostunnel terminated with zero, but expected error due to invalid URI pattern')
        else:
            print_ok("OK (terminated with non-zero exit as expected)")
    finally:
        terminate(ghostunnel)
