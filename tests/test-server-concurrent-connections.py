#!/usr/bin/env python3

# Creates a ghostunnel. Ensures that multiple clients can communicate.

from subprocess import Popen
from multiprocessing import Process
from common import *
import socket
import ssl
import time
import random


def send_data(i, p):
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
    allow_ou = []
    try:
        # create certs
        root = RootCert('root')
        root.create_signed_cert('server')
        for i in range(1, n_clients):
            root.create_signed_cert("client{0}".format(i))
            allow_ou.append("--allow-ou=client{0}".format(i))

        # start ghostunnel
        ghostunnel = run_ghostunnel(['server',
                                     '--listen={0}:13001'.format(LOCALHOST),
                                     '--target={0}:13002'.format(LOCALHOST),
                                     '--keystore=server.p12',
                                     '--status={0}:{1}'.format(LOCALHOST,
                                                               STATUS_PORT),
                                     '--cacert=root.crt'] + allow_ou)

        # clients should be able to communicate all at the same time.
        proc = []
        for i in range(1, n_clients):
            pair = SocketPair(TlsClient("client{0}".format(
                i), 'root', 13001), TcpServer(13002))
            p = Process(target=send_data, args=(i, pair,))
            p.start()
            proc.append(p)
        for p in proc:
            p.join()

        print_ok("OK")
    finally:
        terminate(ghostunnel)
