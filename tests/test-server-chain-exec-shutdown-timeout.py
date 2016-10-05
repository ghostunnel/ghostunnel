#!/usr/bin/env python3

from subprocess import Popen
from common import *
import socket, ssl, time, os, signal

if __name__ == "__main__":
  ghostunnel = None
  try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('server')
    root.create_signed_cert('client')

    # start ghostunnel server with false as child
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:13002'.format(LOCALHOST), '--keystore=server.p12',
      '--shutdown-timeout=1s', '--cacert=root.crt',
      '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--allow-all', '--', 'python3', 'child-process-sigterm-trap.py', '13002'])

    urlopen = lambda path: urllib.request.urlopen(path, cafile='root.crt')

    # block until ghostunnel is up
    TcpClient(STATUS_PORT).connect(20)

    # get child pid
    status = json.loads(str(urlopen("https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    # send sigterm to ghostunnel, wait for child to terminate
    stopped = False
    ghostunnel.terminate()
    for n in range(0, 30):
      try:
        os.kill(status['child_pid'], 0)
        print_ok("child is still alive")
      except:
        stopped = True
        break
      time.sleep(1)

    if not stopped:
      raise Exception('child never terminated')

    # wait for ghostunnel to terminate
    for n in range(0, 90):
      try:
        try:
          ghostunnel.wait(timeout=1)
        except:
          pass
        os.kill(ghostunnel.pid, 0)
        print_ok("ghostunnel is still alive")
      except:
        stopped = True
        break
      time.sleep(1)

    if not stopped:
      raise Exception('ghostunnel did not terminate within 90 seconds')

    print_ok("child terminated")

    print_ok("OK")
  finally:
    terminate(ghostunnel)
