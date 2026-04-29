#!/usr/bin/env python3

"""
Tests that 'ghostunnel service status' for a non-existent service exits
with a non-zero code. Requires Windows and Administrator privileges
(mgr.Connect() requests SC_MANAGER_ALL_ACCESS).
"""

from common import (assert_not_zero, print_ok, require_admin,
                    require_platform, run_ghostunnel)

require_platform('Windows')
require_admin()

ghostunnel = run_ghostunnel([
    'service', 'status', '--service-name', 'ghostunnel-nonexistent-99999',
])
assert_not_zero(ghostunnel)
print_ok("OK")
