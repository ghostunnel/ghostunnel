// Command ghostunnel implements a simple SSL/TLS proxy with mutual
// authentication for securing non-TLS services. Ghostunnel in server mode
// runs in front of a backend server and accepts TLS-secured connections, which
// are then proxied to the (insecure) backend. A backend can be a TCP
// domain/port or a UNIX domain socket. Ghostunnel in client mode accepts
// (insecure) connections through a TCP or UNIX domain socket and proxies them
// to a TLS-secured service.
package main
