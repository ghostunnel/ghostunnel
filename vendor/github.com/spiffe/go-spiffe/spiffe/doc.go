/*
Package spiffe provides a way to make workloads to get automatically rotated
X.509 SVIDs from a SPIFFE Workload API and to use them to establish mTLS
connections with other workloads.

The functions ListenTLS and DialTLS provides a handy way to get
and use the SVIDs for mTLS connections. If more control over the connections is
needed, use the TLSPeer type instead.

A full example is available at:
https://github.com/spiffe/go-spiffe/tree/master/examples/svid-mTLS
*/
package spiffe
