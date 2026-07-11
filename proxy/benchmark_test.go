package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
)

func BenchmarkCopyData(b *testing.B) {
	proxy := proxyForTest(nil, nil)

	for i := range 16 {
		b.Run(fmt.Sprintf("%d bytes", 1<<i), func(b *testing.B) {
			benchmarkCopyData(b, proxy, 1<<i)
		})
	}
}

func benchmarkCopyData(b *testing.B, proxy *Proxy, size int) {
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		srcIn, srcOut := net.Pipe()
		dstIn, dstOut := net.Pipe()
		defer func() {
			srcIn.Close()
			srcOut.Close()
			dstIn.Close()
			dstOut.Close()
		}()

		go func() {
			buf := make([]byte, size)
			for i := range size {
				buf[i] = byte(i % (1 << 8))
			}
			_, _ = srcIn.Write(buf)
			srcIn.Close()
		}()

		go func() {
			var err error
			buf := make([]byte, 1<<10)
			for err == nil {
				_, err = dstOut.Read(buf)
			}
			if err != nil && err != io.EOF && !isClosedConnectionError(err) {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		}()

		proxy.copyData(dstIn, srcOut)
	}
}

// benchTCPConn is a net.Conn stub whose addresses are *net.TCPAddr, so
// proxyProtoHeader exercises the real TCPv4 transportProtocol branch rather
// than falling through to UNSPEC.
type benchTCPConn struct {
	net.Conn
}

func (benchTCPConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 51000}
}

func (benchTCPConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 443}
}

// BenchmarkProxyProtoHeader measures construction of the PROXY protocol v2
// header on the accept hot path (proxyProtoHeader in proxy.go). It runs
// once per connection when a PROXY-protocol mode is enabled, and reports the
// allocations that construction performs. TLSFull additionally copies the peer
// cert DER, so it is benchmarked separately from TLS mode.
func BenchmarkProxyProtoHeader(b *testing.B) {
	_, leaf := benchSelfSignedCert(b)
	conn := benchTCPConn{}

	state := &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
		NegotiatedProtocol: "h2",
		ServerName:         "example.com",
		PeerCertificates:   []*x509.Certificate{leaf},
	}

	for _, tc := range []struct {
		name string
		mode ProxyProtocolMode
	}{
		{"conn", ProxyProtocolConn},
		{"tls", ProxyProtocolTLS},
		{"tls-full", ProxyProtocolTLSFull},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = proxyProtoHeader(conn, state, tc.mode)
			}
		})
	}
}
