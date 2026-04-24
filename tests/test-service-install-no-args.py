#!/usr/bin/env python3

"""
Tests that 'ghostunnel service install' without proxy arguments (no '--'
separator followed by server/client args) exits with a non-zero code and
a clear error message. Does not require Administrator privileges since
validation fails before connecting to the SCM.
"""

import subprocess

from common import (assert_not_zero, print_ok, require_platform,
                    run_ghostunnel)

require_platform('Windows')

ghostunnel = run_ghostunnel(
    ['service', 'install', '--service-name', 'ghostunnel-pytest-noargs'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
assert_not_zero(ghostunnel)
print_ok("OK")
