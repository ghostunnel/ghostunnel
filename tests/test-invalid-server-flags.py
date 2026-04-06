#!/usr/bin/env python3

from common import LOCALHOST, RootCert, STATUS_PORT, print_ok, run_ghostunnel, terminate, LISTEN_PORT, TARGET_PORT

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')

    # start ghostunnel with bad access flags
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
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

    # start ghostunnel with bad listen addr
    ghostunnel = run_ghostunnel(['server',
                                 '--listen=invalid',
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--allow-all',
                                 '--keystore=server.p12',
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

    # start ghostunnel with bad URI pattern
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--allow-uri=spiffe://**/**/**',
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

    # start ghostunnel with bad cert/key flags
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=server.crt',
                                 '--allow-uri=spiffe://**/**/**',
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

    # start ghostunnel with bad cert/key flags
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--cert=server.crt',
                                 '--key=server.key',
                                 '--keystore=server.p12',
                                 '--allow-uri=spiffe://**/**/**',
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

    # start ghostunnel with ACME requested but no email address specified
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--auto-acme-testca=https://acme-staging-v02.api.letsencrypt.org/directory',
                                 '--auto-acme-cert=example.com',
                                 '--auto-acme-agree-to-tos',
                                 '--disable-authentication'])

    # wait for ghostunnel to exit and make sure error code is not zero
    ret = ghostunnel.wait(timeout=20)
    if ret == 0:
        raise Exception(
            'ghostunnel terminated with zero, though flags were invalid')
    else:
        print_ok("OK (terminated)")

    # start ghostunnel with ACME requested but without agree-to-tos
    ghostunnel = run_ghostunnel(['server',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--auto-acme-testca=https://acme-staging-v02.api.letsencrypt.org/directory',
                                 '--auto-acme-cert=example.com',
                                 '--auto-acme-email=admin@example.com',
                                 '--disable-authentication'])

    # wait for ghostunnel to exit and make sure error code is not zero
    ret = ghostunnel.wait(timeout=20)
    if ret == 0:
        raise Exception(
            'ghostunnel terminated with zero, though flags were invalid')
    else:
        print_ok("OK (terminated)")
finally:
    terminate(ghostunnel)
