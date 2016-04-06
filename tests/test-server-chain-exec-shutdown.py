#!/usr/bin/env python3

from subprocess import Popen
from test_common import *
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # start ghostunnel server with false as child
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=client.p12',
      '--cacert=root.crt', '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--allow-all', '--', 'nc', '-kl', LOCALHOST, '13002'])

    urlopen = lambda path: urllib.request.urlopen(path, cafile='root.crt')

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(20)

    # get child pid
    status = json.loads(str(urlopen("https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    # send sigterm to ghostunnel, wait for child to terminate
    stopped = False
    ghostunnel.terminate()
    for n in range(0, 10):
      try:
        os.kill(status['child_pid'], 0)
        print_ok("child is still alive")
      except:
        stopped = True
        break
      time.sleep(1)

    if not stopped:
      raise Exception('child never terminated')

    print_ok("child terminated")

    print_ok("OK")
  finally:
    terminate(ghostunnel)
