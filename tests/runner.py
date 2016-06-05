#!/usr/bin/env python3

from subprocess import run
import sys, time, subprocess

test = sys.argv[1]
path = './%s.py' % test

print("=== RUN   %s" % test)

start = time.time()
proc = run([path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
end = time.time()

if proc.returncode == 0:
  print("=== PASS: %s (%.2fs)" % (test, end - start))
else:
  sys.stdout.buffer.write(proc.stdout)
  sys.stdout.buffer.write(proc.stderr)
  print("=== FAIL: %s (%.2fs)" % (test, end - start))

sys.exit(proc.returncode)
