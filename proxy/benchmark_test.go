package proxy

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func BenchmarkCopyData(b *testing.B) {
	proxy := New(nil, 10*time.Second, 10*time.Second, nil, &testLogger{}, LogEverything, false)

	for i := 0; i < 16; i++ {
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
			for i := 0; i < size; i++ {
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
