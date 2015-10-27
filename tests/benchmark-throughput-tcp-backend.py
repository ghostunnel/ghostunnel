#!/usr/local/bin/python

from subprocess import Popen
from test_common import create_root_cert, create_signed_cert, LOCALHOST, SocketPair, print_ok, cleanup_certs
from timeit import default_timer as timer
import socket, ssl, tempfile, os

if __name__ == "__main__":
  ghostunnel = None
  try:
    # Step 1: create certs
    create_root_cert('root')
    create_signed_cert('server', 'root')
    create_signed_cert('client1', 'root')

    # Step 2: start ghostunnel
    ghostunnel = Popen(['../ghostunnel', '--listen={0}:13001'.format(LOCALHOST),
        '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--storepass=', '--cacert=root.crt', '--allow-ou=client1'])

    # Step 3: connect with client1, confirm that the tunnel is up
    pair = SocketPair('client1', 13001, 13002)
    pair.validate_can_send_from_server('hello world', '1: server -> client')
    pair.validate_can_send_from_client('hello world', '1: client -> server')

    # Step 4: send large chunks of data, measure throughput
    start = timer()

    print_ok('Sending data...')

    b = b'\x41'
    n = 100*1024*1024
    c = 5*1024
    r = n
    while r > 0:
        block = b*c
        pair.client_sock.send(b*c)
        resp = pair.server_sock.recv(len(b)*c)
        r -= len(b)*c

    print_ok('Sent %d bytes' % (n-r))

    end = timer()
    print_ok('Time elapsed: %.2f sec' % (end - start))
    print_ok('Throughput: %.2f MiB/sec' % ((n-r)/(end-start)/1024/1024))

    print_ok('OK')
  finally:
    cleanup_certs(['root', 'server', 'client1'])
    if ghostunnel:
      ghostunnel.kill()
