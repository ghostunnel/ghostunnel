package policy
import input
default allow := false
allow {
    input.certificate.DNSNames[_] == "client1"
}
