#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # start ghostunnel with bad flags
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                     '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                     '--connect-proxy=ftp://invalid',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # wait for ghostunnel to exit and make sure error code is not zero
        ret = ghostunnel.wait(timeout=20)
        if ret == 0:
            raise Exception(
                'ghostunnel terminated with zero, though flags were invalid')
        else:
            print_ok("OK (terminated)")
    finally:
        terminate(ghostunnel)
