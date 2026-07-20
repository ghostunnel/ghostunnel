/*-
 * Copyright 2026 Ghostunnel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	metrics "github.com/rcrowley/go-metrics"
)

// benchSelfSignedCert generates a self-signed ECDSA P-256 certificate usable as
// both a server and client certificate, and as its own CA. It mirrors the
// selfSignedCert helper in proxy_test.go but accepts testing.TB so it can be
// used from benchmarks. It returns the tls.Certificate and the parsed leaf.
func benchSelfSignedCert(tb testing.TB) (tls.Certificate, *x509.Certificate) {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "test-cn",
			OrganizationalUnit: []string{"test-ou"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		tb.Fatal(err)
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		tb.Fatal(err)
	}

	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: leaf}, leaf
}

// BenchmarkConnectionChurn drives the full connection-acceptance hot path under
// load: a real TCP listener wrapped in TLS, a real echo backend, and the proxy
// accept loop. Each iteration opens a fresh mutually-authenticated TLS
// connection (no client session cache, so every connection is a full
// handshake), sends one byte, reads the echo, and closes. Run with
// -cpu=1,4,8 to observe how the per-connection accept path scales across cores.
//
// Unlike BenchmarkCopyData (which uses net.Pipe and measures only the
// steady-state copy loop), this benchmark exercises real sockets and a
// *tls.Conn, so it observes the real per-connection accept path (handshake,
// metric bookkeeping, deadlines at close, the single accept goroutine). The
// incoming listener uses plain tls.NewListener; the certloader per-connection
// tls.Config clone is measured separately by BenchmarkGetServerConfig in the
// certloader package.
//
// This variant uses live metrics (nil handles fall back to the default registry
// in proxy.New), i.e. the path taken when a metrics sink is configured. It is
// the figure for the metrics-enabled (sink-configured) accept path.
func BenchmarkConnectionChurn(b *testing.B) {
	benchmarkConnectionChurn(b, nil)
}

// BenchmarkConnectionChurnNoSink runs the identical churn workload but with
// no-op metric handles (proxy.NilMetrics) — the path Ghostunnel takes when
// started with no metrics sink (--status, --metrics-graphite and --metrics-url
// all unset, the default). Comparing it against BenchmarkConnectionChurn
// isolates the per-connection metric-bookkeeping cost removed by skipping metric
// collection in the default configuration.
//
// Note: each iteration performs a full ECDSA handshake, which dominates
// per-connection CPU, so the metric delta is small relative to total time and
// is clearest under contention (-cpu=4,8), where the two shared go-metrics
// timers' mutex is hottest. A mutex/block profile remains the most direct way
// to see the timer contention.
func BenchmarkConnectionChurnNoSink(b *testing.B) {
	benchmarkConnectionChurn(b, NilMetrics())
}

// BenchmarkConnMetricsBookkeeping isolates the per-connection metric updates the
// accept path performs (the two timers plus the open/total/success counters),
// with no handshake or network in the loop. This is the measurement that
// isolates that cost directly: the metrics=live column records to real
// go-metrics handles, metrics=nosink uses proxy.NilMetrics, and the gap is the
// CPU — and, under -cpu=4,8, the lock contention — removed when no metrics sink
// is configured. The end-to-end BenchmarkConnectionChurn cannot show this
// because the ~1ms ECDSA handshake dwarfs this sub-microsecond bookkeeping.
//
// Compare the two columns directly with:
//
//	go test -run '^$' -bench BenchmarkConnMetricsBookkeeping -count=10 -cpu=1,4,8 ./proxy/ > m.txt
//	benchstat -col /metrics m.txt
func BenchmarkConnMetricsBookkeeping(b *testing.B) {
	// A fresh registry for the live case so it never touches the package
	// default registry (and so repeated runs don't accumulate state).
	run := func(b *testing.B, m *Metrics) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			start := time.Now()
			for pb.Next() {
				// Mirrors the per-connection sequence in Accept/forceHandshake.
				m.OpenCounter.Inc(1)
				m.TotalCounter.Inc(1)
				m.HandshakeTimer.UpdateSince(start)
				m.SuccessCounter.Inc(1)
				m.OpenCounter.Dec(1)
				m.ConnTimer.UpdateSince(start)
			}
		})
	}
	b.Run("metrics=live", func(b *testing.B) { run(b, LiveMetrics(metrics.NewRegistry())) })
	b.Run("metrics=nosink", func(b *testing.B) { run(b, NilMetrics()) })
}

// benchmarkConnectionChurn is the shared body for the live and no-sink churn
// benchmarks; connMetrics selects which metric handles the proxy records to
// (nil → default registry, NilMetrics → no-op).
func benchmarkConnectionChurn(b *testing.B, connMetrics *Metrics) {
	serverCert, leaf := benchSelfSignedCert(b)

	pool := x509.NewCertPool()
	pool.AddCert(leaf)

	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		// No ClientSessionCache: every dial performs a full handshake, which
		// is the connection-churn case this benchmark is meant to stress.
	}

	// Echo backend: accept each connection, read one request, echo it, then
	// close. The backend is deliberately the *active closer*: that makes the
	// load generator's client sockets passive closers, so their ephemeral
	// ports are released immediately instead of lingering in TIME_WAIT. Without
	// this, high parallel churn on localhost exhausts the ephemeral port range
	// ("can't assign requested address") long before the proxy is the
	// bottleneck.
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer backend.Close()
	go func() {
		for {
			conn, err := backend.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 64)
				if n, err := c.Read(buf); err == nil && n > 0 {
					_, _ = c.Write(buf[:n])
				}
				_ = c.Close()
			}(conn)
		}
	}()

	// Incoming side: plain TLS listener wrapping a real TCP socket.
	rawIncoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	incoming := tls.NewListener(rawIncoming, serverConfig)

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backend.Addr().String())
	}

	// Unlimited semaphore (0) so concurrency isn't capped — proxyForTest pins
	// it at 1, which would serialize the churn we want to measure. No logging.
	p := New(incoming, 5*time.Second, 5*time.Second, 0, 0, dialer, &testLogger{}, 0, ProxyProtocolOff, connMetrics)
	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()

	incomingAddr := incoming.Addr().String()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 64)
		for pb.Next() {
			conn, err := tls.Dial("tcp", incomingAddr, clientConfig)
			if err != nil {
				b.Error(err)
				return
			}
			if _, err := conn.Write([]byte("A")); err != nil {
				b.Error(err)
				_ = conn.Close()
				return
			}
			// Drain to EOF: receive the echo and then the backend-initiated
			// close, so this client is the passive closer (see backend above).
			got := 0
			for {
				n, err := conn.Read(buf)
				got += n
				if err != nil {
					if !errors.Is(err, io.EOF) {
						b.Error(err)
					}
					break
				}
			}
			if got == 0 {
				b.Error("no echo received from backend")
			}
			_ = conn.Close()
		}
	})
}
