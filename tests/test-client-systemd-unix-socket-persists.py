#!/usr/bin/env python3

"""
Regression test: with --listen=systemd:NAME pointing at a UNIX socket,
ghostunnel must NOT unlink the socket path on shutdown. The service manager
owns the path; deleting it from the child destroys the unit's SocketUser /
SocketGroup / SocketMode settings and breaks handoff across exec restarts.

This test emulates the service-manager handoff directly: this Python process
binds the UNIX socket and keeps the listener FD open for the duration of the
test. If sock_path goes missing after ghostunnel exits, it can only be
because ghostunnel itself unlinked it.
"""

import os
import shutil
import socket as pysocket
import subprocess
import tempfile
import time
from common import LOCALHOST, RootCert, print_ok, require_platform, _GHOSTUNNEL_BINARY, coverage_pod_dir

require_platform('Linux')

# Short tmpdir to stay under AF_UNIX's sun_path length limit.
sock_dir = tempfile.mkdtemp(prefix='gt-')
sock_path = os.path.join(sock_dir, 'client.sock')

ghostunnel = None
unix_sock = None

try:
    # create certs
    root = RootCert('root')
    root.create_signed_cert('client')

    # Bind the UNIX socket exactly as a service manager would.
    unix_sock = pysocket.socket(pysocket.AF_UNIX, pysocket.SOCK_STREAM)
    unix_sock.bind(sock_path)
    unix_sock.listen()

    # Coverage env mirrors run_ghostunnel().
    env = os.environ.copy()
    env['GOCOVERDIR'] = coverage_pod_dir()
    env['LISTEN_FDS'] = '1'
    env['LISTEN_FDNAMES'] = 'client'

    # systemd's protocol expects the inherited FD at position 3. Python's
    # pass_fds preserves the parent's FD numbers, so dup the socket into
    # position 3 inside the child via preexec_fn. LISTEN_PID must equal the
    # child's PID, so a shell prologue sets it post-fork and execs ghostunnel
    # (preserving the PID).
    sock_fd = unix_sock.fileno()

    def position_fd():
        os.dup2(sock_fd, 3)

    cmd = [
        'sh', '-c', 'export LISTEN_PID=$$; exec "$@"', '--',
        _GHOSTUNNEL_BINARY,
        'client',
        '--listen=systemd:client',
        # Target is never connected to — we only exercise startup + shutdown.
        '--target={0}:9'.format(LOCALHOST),
        '--keystore=client.p12',
        '--cacert=root.crt',
        '--shutdown-timeout=1s',
        '--close-timeout=1s',
    ]
    print_ok('running: ' + ' '.join(cmd))
    ghostunnel = subprocess.Popen(
        cmd, env=env, preexec_fn=position_fd, pass_fds=(3,))

    # Give ghostunnel a moment to wire up its listener.
    time.sleep(2)
    if ghostunnel.poll() is not None:
        raise Exception(
            'ghostunnel exited prematurely with code {0}'.format(ghostunnel.returncode))

    # SIGTERM and wait for graceful shutdown.
    ghostunnel.terminate()
    ghostunnel.wait(timeout=10)

    # Python still holds unix_sock open. The path can only be missing if
    # ghostunnel explicitly unlinked it — which is the bug under test.
    if not os.path.exists(sock_path):
        raise Exception(
            'UNIX socket {0} was unlinked on ghostunnel shutdown'.format(sock_path))

    print_ok('OK: systemd-managed UNIX socket persisted after termination')
finally:
    if ghostunnel and ghostunnel.poll() is None:
        ghostunnel.kill()
    if unix_sock:
        unix_sock.close()
    shutil.rmtree(sock_dir, ignore_errors=True)
