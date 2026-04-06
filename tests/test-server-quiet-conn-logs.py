#!/usr/bin/env python3

"""
Ensures that --quiet=conns disables logging about new connections.
"""

from common import LOCALHOST, RootCert, STATUS_PORT, TcpClient, TlsClient, TcpServer, print_ok, run_ghostunnel, terminate, SocketPair, urlopen, LISTEN_PORT, TARGET_PORT
import subprocess
import json

ghostunnel = None
try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel
    # hack: point target to STATUS_PORT so that /_status doesn't 503.
    ghostunnel = run_ghostunnel(['server',
                                 '--quiet=conns',
                                 '--listen={0}:{1}'.format(LOCALHOST, LISTEN_PORT),
                                 '--target={0}:{1}'.format(LOCALHOST, TARGET_PORT),
                                 '--keystore=server.p12',
                                 '--cacert=root.crt',
                                 '--allow-ou=client',
                                 '--status={0}:{1}'.format(LOCALHOST,
                                                           STATUS_PORT)],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(20)

    # send some requests to status endpoints
    json.loads(str(urlopen(
        'https://{0}:{1}/_metrics'.format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    # send some data through proxy
    pair1 = SocketPair(
            TlsClient('client', 'root', LISTEN_PORT), TcpServer(TARGET_PORT))
    pair1.validate_can_send_from_client('toto', 'works')
    pair1.validate_can_send_from_server('toto', 'works')
    pair1.cleanup()

    terminate(ghostunnel)

    # make sure no logs printed
    out, err = ghostunnel.communicate()

    print('stdout (len={0}):'.format(len(out)))
    print(out)
    print('stderr (len={0}):'.format(len(err)))
    print(err)

    if 'opening pipe' in err.decode('utf-8'):
        raise Exception('ghostunnel logged connection log to stderr with --quiet=conns')

    print_ok('OK')
finally:
    terminate(ghostunnel)
