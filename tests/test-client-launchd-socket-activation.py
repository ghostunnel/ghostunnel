#!/usr/bin/env python3

"""
Spins up a client and tests launchd socket activation (success path).
"""

import os
import subprocess
from common import (LISTEN_PORT, STATUS_PORT, RootCert, TcpClient,
                    print_ok, require_platform, _GHOSTUNNEL_BINARY,
                    _COVERAGE_DIR, _WORK_DIR, _extra_port_sockets)

require_platform('Darwin')

for _s in _extra_port_sockets:
    _s.close()
_extra_port_sockets.clear()

LABEL = 'dev.ghostunnel.test.launchd.{0}'.format(os.getpid())
PLIST_PATH = os.path.join(_WORK_DIR, '{0}.plist'.format(LABEL))
UID = os.getuid()
DOMAIN = 'gui/{0}'.format(UID)
COVERDIR = os.path.join(_COVERAGE_DIR, 'integration')
os.makedirs(COVERDIR, exist_ok=True)

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array>
    <string>{binary}</string>
    <string>client</string>
    <string>--listen=launchd:Listener</string>
    <string>--target=127.0.0.1:{status_port}</string>
    <string>--keystore={workdir}/client.p12</string>
    <string>--cacert={workdir}/root.crt</string>
    <string>--status=launchd:Status</string>
    <string>--shutdown-timeout=1s</string>
    <string>--close-timeout=1s</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>GOCOVERDIR</key><string>{coverdir}</string>
  </dict>
  <key>WorkingDirectory</key><string>{workdir}</string>
  <key>StandardOutPath</key><string>{workdir}/launchd.out.log</string>
  <key>StandardErrorPath</key><string>{workdir}/launchd.err.log</string>
  <key>Sockets</key><dict>
    <key>Listener</key><dict>
      <key>SockServiceName</key><string>{listen_port}</string>
      <key>SockType</key><string>stream</string>
      <key>SockFamily</key><string>IPv4</string>
      <key>SockNodeName</key><string>127.0.0.1</string>
    </dict>
    <key>Status</key><dict>
      <key>SockServiceName</key><string>{status_port}</string>
      <key>SockType</key><string>stream</string>
      <key>SockFamily</key><string>IPv4</string>
      <key>SockNodeName</key><string>127.0.0.1</string>
    </dict>
  </dict>
</dict></plist>
""".format(label=LABEL, binary=_GHOSTUNNEL_BINARY, workdir=_WORK_DIR,
           listen_port=LISTEN_PORT, status_port=STATUS_PORT, coverdir=COVERDIR)

bootstrapped = False
try:
    root = RootCert('root')
    root.create_signed_cert('client')

    with open(PLIST_PATH, 'w') as f:
        f.write(PLIST)

    subprocess.check_call(['launchctl', 'bootstrap', DOMAIN, PLIST_PATH])
    bootstrapped = True

    TcpClient(STATUS_PORT).connect(20)
    print_ok("OK")
finally:
    if bootstrapped:
        subprocess.call(['launchctl', 'bootout', '{0}/{1}'.format(DOMAIN, LABEL)])
