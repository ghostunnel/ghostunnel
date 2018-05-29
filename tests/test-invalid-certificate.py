#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')

        # start ghostunnel with bad cert
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client.key',
                                     '--cacert=root.crt',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT)])

        # wait for ghostunnel to exit and make sure error code is not zero
        ret = ghostunnel.wait(timeout=20)
        if ret == 0:
            raise Exception(
                'ghostunnel terminated with zero, though cert was invalid')
        else:
            print_ok("OK (terminated)")
    finally:
        terminate(ghostunnel)
