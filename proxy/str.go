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

func connStatsString(sent, recv int64, open time.Duration) string {
	if sent < 0 || recv < 0 || open == 0 {
		return ""
	}

	return fmt.Sprintf("[sent %s, recv %s, open %s]", bytesWithUnit(sent), bytesWithUnit(recv), open.String())
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
