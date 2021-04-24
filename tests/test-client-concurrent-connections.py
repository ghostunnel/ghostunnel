#!/usr/bin/env python3

"""
Ensures that multiple servers can communicate.
"""

from multiprocessing import Process
from common import LOCALHOST, RootCert, STATUS_PORT, SocketPair, TcpClient, TlsServer, print_ok, run_ghostunnel, terminate
import time
import random


def send_data(i):
    p = SocketPair(TcpClient(13001), TlsServer("server{0}".format(i), 'root', 13002))
    counter = 0
    while counter < 100:
        r = random.random()
        if r < 0.4:
            time.sleep(r)
            continue
        counter += 1
        if r < 0.7:
            p.validate_can_send_from_client(
                "blah blah blah", "{0}:{1} client -> server".format(i, counter))
        else:
            p.validate_can_send_from_server(
                "blah blah blah", "{0}:{1} server -> client".format(i, counter))
    r = random.random()
    if r < 0.5:
        p.validate_closing_client_closes_server(
            "{0} client close -> server close".format(i))
    else:
        p.validate_closing_server_closes_client(
            "{0} server close -> client close".format(i))


if __name__ == "__main__":
    ghostunnel = None
    n_clients = 10
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('client')
        for n in range(1, n_clients):
            root.create_signed_cert("server{0}".format(n))

        # start ghostunnel
        ghostunnel = run_ghostunnel(['client',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=client.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt'])

        # servers should be able to communicate all at the same time.
        procs = []
        for n in range(1, n_clients):
            proc = Process(target=send_data, args=(n,))
            proc.start()
            procs.append(proc)
        for proc in procs:
            proc.join()

        print_ok("OK")
    finally:
        terminate(ghostunnel)
