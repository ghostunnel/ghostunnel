#!/usr/bin/env python3

"""
Tests that 'ghostunnel service install' with an invalid service name
(containing special characters) exits with a non-zero code. Does not
require Administrator privileges since name validation fails before
connecting to the SCM.
"""

import subprocess

from common import (assert_not_zero, print_ok, require_platform,
                    run_ghostunnel)

require_platform('Windows')

ghostunnel = run_ghostunnel(
    ['service', 'install', '--service-name', 'bad/name<>',
     '--', 'server', '--listen', ':8443', '--target', 'localhost:8080',
     '--keystore=server.p12', '--cacert=root.crt', '--allow-ou=test'],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
assert_not_zero(ghostunnel)
print_ok("OK")
