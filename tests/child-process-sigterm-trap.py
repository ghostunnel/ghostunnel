#!/usr/bin/env python3

from common import *
import sys, signal

# Be naughty and ignore SIGTERM to simulate hanging child
signal.signal(signal.SIGTERM, signal.SIG_IGN)

# Start a server that listens for incoming connections
try:
    print_ok("child starting up on port %s" % sys.argv[1])
    s = TcpServer(int(sys.argv[1]))
    s.listen()
    while True:
        try:
            s.socket, _ = s.listener.accept()
            s.socket.settimeout(TIMEOUT)
        except:
            pass
finally:
    s.cleanup()

print_ok("child exiting")
