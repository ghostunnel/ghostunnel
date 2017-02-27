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

    # start ghostunnel
    ghostunnel = run_ghostunnel(['server', '--listen={0}:13001'.format(LOCALHOST),
      '--target={0}:{1}'.format(LOCALHOST, STATUS_PORT), '--keystore=server.p12',
      '--cacert=root.crt', '--allow-ou=client', '--status={0}:{1}'.format(LOCALHOST, STATUS_PORT),
      '--', 'python3', 'child-process-waits-forever.py'])

    # wait for startup
    TlsClient(None, 'root', STATUS_PORT).connect(20, 'server')

    # get child pid
    urlopen = lambda path: urllib.request.urlopen(path, cafile='root.crt')
    status = json.loads(str(urlopen("https://{0}:{1}/_status".format(LOCALHOST, STATUS_PORT)).read(), 'utf-8'))

    # shut down ghostunnel with connection open, make sure it doesn't hang
    print_ok('terminating child via signal')
    for n in range(0, 90):
      try:
        try:
          os.kill(status['child_pid'], signal.SIGTERM)
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

    print_ok("OK (terminated)")
  finally:
    terminate(ghostunnel)
      
