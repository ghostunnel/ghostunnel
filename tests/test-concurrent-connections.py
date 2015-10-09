#!/usr/local/bin/python

# Creates a ghostunnel. Ensures that multiple clients can communicate.

from subprocess import Popen
from multiprocessing import Process
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
import socket, ssl, time, random

def send_data(i, p):
  counter = 0
  while counter < 100:
    r = random.random()
    if r < 0.4:
      time.sleep(r)
      continue
    counter+=1
    if r < 0.7:
      p.validate_can_send_from_client("blah blah blah", "{0}:{1} client -> server".format(i, counter))
    else:
      p.validate_can_send_from_server("blah blah blah", "{0}:{1} server -> client".format(i, counter))
  r = random.random()
  if r < 0.5:
    p.validate_closing_client_closes_server("{0} client close -> server close".format(i))
  else:
    p.validate_closing_server_closes_client("{0} server close -> client close".format(i))


if __name__ == "__main__":
  ghostunnel = None
  n_clients = 10
  certs = ['root', 'server']
  allow_ou = []
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    for i in range(1, n_clients):
      create_signed_cert("client{0}".format(i), 'root')
      certs.append("client{0}".format(i))
      allow_ou.append("--allow-ou=client{0}".format(i))

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13000'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt'] + allow_ou)

    # Step 3: clients should be able to communicate all at the same time.
    proc = []
    for i in range(1, n_clients):
      pair = SocketPair("client{0}".format(i), 13001, 13000)
      p = Process(target=send_data, args=(i,pair,))
      p.start()
      proc.append(p)
    for p in proc:
      p.join()

    print_ok("OK")
  finally:
    cleanup_certs(certs)
    if ghostunnel:
      ghostunnel.kill()
