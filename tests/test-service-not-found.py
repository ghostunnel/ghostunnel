#!/usr/bin/env python3

"""
Tests that 'service start', 'service stop', and 'service uninstall' all
exit with a non-zero code when the named service does not exist. Requires
Windows and Administrator privileges (SCM access).

Complements test-service-status-not-found.py which covers 'service status'.
"""

from common import (assert_not_zero, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

NONEXISTENT = 'ghostunnel-nonexistent-99999'

# start
proc = run_ghostunnel([
    'service', 'start', '--service-name', NONEXISTENT,
])
assert_not_zero(proc)
print_ok("start non-existent: correctly rejected")

# stop
proc = run_ghostunnel([
    'service', 'stop', '--service-name', NONEXISTENT,
])
assert_not_zero(proc)
print_ok("stop non-existent: correctly rejected")

# uninstall
proc = run_ghostunnel([
    'service', 'uninstall', '--service-name', NONEXISTENT,
])
assert_not_zero(proc)
print_ok("uninstall non-existent: correctly rejected")

print_ok("OK")
