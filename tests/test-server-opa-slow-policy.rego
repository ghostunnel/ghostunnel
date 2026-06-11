package policy

import input

default allow := false

# Pathological rule that performs a comprehension over a very large range.
# Evaluation reliably takes well over a second so the OPAQueryTimeout context
# (wired from --connect-timeout) fires and the handshake is rejected.
allow if {
	some _ in numbers.range(1, 50000000)
	input.certificate.DNSNames[_] == "client1"
}
