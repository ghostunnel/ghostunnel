package proxy

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

var byteUnits []string = []string{
	"KiB",
	"MiB",
	"GiB",
	"TiB",
	"PiB",
}

func bytesWithUnit(n int64) string {
	if n < (1 << 10) {
		return fmt.Sprintf("%d bytes", n)
	}
	for _, unit := range byteUnits {
		if n < (1 << 20) {
			return fmt.Sprintf("%1.1f %s", float32(n)/float32(1024), unit)
		}
		n = n >> 10
	}
	return fmt.Sprintf("%1.1f EiB", float32(n)/float32(1024))
}

func connStatsString(forwarded, returned int64, open time.Duration) string {
	if forwarded < 0 || returned < 0 || open == 0 {
		return ""
	}
	if open > time.Millisecond {
		open = open.Round(time.Millisecond)
	}

	return fmt.Sprintf("[forwarded %s, returned %s, open %s]", bytesWithUnit(forwarded), bytesWithUnit(returned), open.String())
}

func peerCertificatesString(conn net.Conn) string {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		if len(tlsConn.ConnectionState().PeerCertificates) > 0 {
			return tlsConn.ConnectionState().PeerCertificates[0].Subject.String()
		}

		return "no cert"
	}

	return "no tls"
}
