#!/usr/bin/env python3

from common import LOCALHOST, RootCert, run_ghostunnel, terminate, assert_not_zero, LISTEN_PORT, TARGET_PORT

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # start ghostunnel with bad flags
        ghostunnel1 = run_ghostunnel(['client',
                                      '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                      '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                      '--keystore=server.p12',
                                      '--disable-authentication',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel1)

        ghostunnel2 = run_ghostunnel(['client',
                                      '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                      '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                      '--cert=server.crt',
                                      '--key=server.key',
                                      '--disable-authentication',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel2)

        ghostunnel3 = run_ghostunnel(['client',
                                      '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                      '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                      '--key=server.crt',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel3)

        ghostunnel4 = run_ghostunnel(['client',
                                      '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                      '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                      '--disable-authentication',
                                      '--key=server.key',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel4)

        ghostunnel5 = run_ghostunnel(['client',
                                      '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                      '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                      '--disable-authentication',
                                      '--cert=server.key',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel5)
    finally:
        terminate(ghostunnel1)
        terminate(ghostunnel2)
        terminate(ghostunnel3)
        terminate(ghostunnel4)
        terminate(ghostunnel5)
