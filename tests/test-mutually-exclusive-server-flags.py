#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, assert_not_zero

if __name__ == "__main__":
    ghostunnel = None
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')

        # start ghostunnel with bad flags
        ghostunnel1 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--keystore=server.p12',
                                      '--disable-authentication',
                                      '--allow-cn=test.example.com',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel1)

        ghostunnel2 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--keystore=server.p12',
                                      '--cert=server.crt',
                                      '--key=server.key',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel2)

        ghostunnel3 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--cert=server.crt',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel3)

        ghostunnel4 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--key=server.crt',
                                      '--cacert=root.crt'])
        assert_not_zero(ghostunnel4)

        ghostunnel5 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--cert=server.crt',
                                      '--key=server.key',
                                      '--auto-acme-cert=www.example.com',
                                      '--auto-acme-email=admin@example.com',
                                      '--auto-acme-testca=https://acme-staging-v02.api.letsencrypt.org/directory',
                                      '--auto-acme-agree-to-tos'])
        assert_not_zero(ghostunnel5)

        ghostunnel6 = run_ghostunnel(['server',
                                      '--listen={0}:13001'.format(LOCALHOST),
                                      '--target={0}:13002'.format(LOCALHOST),
                                      '--use-workload-api',
                                      '--auto-acme-cert=www.example.com',
                                      '--auto-acme-email=admin@example.com',
                                      '--auto-acme-testca=https://acme-staging-v02.api.letsencrypt.org/directory',
                                      '--auto-acme-agree-to-tos'])
        assert_not_zero(ghostunnel6)

    finally:
        terminate(ghostunnel1)
        terminate(ghostunnel2)
        terminate(ghostunnel3)
        terminate(ghostunnel4)
        terminate(ghostunnel5)
        terminate(ghostunnel6)
