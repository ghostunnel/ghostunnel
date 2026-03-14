// Package certloader provides abstractions over certificates that can be used
// for clients and servers to make runtime reloading easier. It supports reading
// certificates from PEM files, PKCS#12 keystores, PKCS#11 hardware modules,
// the SPIFFE Workload API, ACME, and the macOS/Windows keychain.
package certloader
