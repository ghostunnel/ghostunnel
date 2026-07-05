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

package certloader

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"testing"
)

// benchCertificate is a faithful stand-in for a real Certificate on the hot
// path: it embeds baseCertificate, so GetCertificate/GetClientCertificate/
// GetTrustStore are the same atomic.Pointer.Load() the production types use
// (see baseCertificate in certificate.go) — pointer loads, zero allocation. This is
// deliberately NOT the mockCertificateWithPrivateKey used elsewhere in tests:
// that mock's GetTrustStore allocates a fresh x509.NewCertPool() on every call,
// which would charge GetServerConfig/GetClientConfig an allocation that the
// real code (a pointer load) never performs, contaminating the alloc count.
type benchCertificate struct {
	baseCertificate
}

func (b *benchCertificate) Reload() error { return nil }

func newBenchCertificate() *benchCertificate {
	c := &benchCertificate{}
	// Non-nil PrivateKey so CanServe() reports true; the values are loaded via
	// the same atomic pointers production uses, so reads are allocation-free.
	c.cachedCertificate.Store(&tls.Certificate{PrivateKey: struct{}{}})
	c.cachedCertPool.Store(x509.NewCertPool())
	return c
}

// benchBaseConfig mirrors the shape of the *tls.Config Ghostunnel builds in
// tls.go (min version, ALPN protocols, cipher suite list) so that the
// per-connection Clone() performed by GetServerConfig/GetClientConfig copies
// representative slice fields.
func benchBaseConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// BenchmarkGetServerConfig measures the per-accepted-connection cost of
// certloader.Listener.Accept -> TLSServerConfig.GetServerConfig (listener.go).
// The serial sub-benchmark reports allocs/op; the parallel one (run with
// -cpu=1,4,8) shows how the clone cost behaves under concurrency.
func BenchmarkGetServerConfig(b *testing.B) {
	source := TLSConfigSourceFromCertificate(newBenchCertificate(), log.New(io.Discard, "", 0))
	cfg, err := source.GetServerConfig(benchBaseConfig())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = cfg.GetServerConfig()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = cfg.GetServerConfig()
			}
		})
	})
}

// BenchmarkGetClientConfig measures the per-dial cost of the matching client
// path (dialer.go).
func BenchmarkGetClientConfig(b *testing.B) {
	source := TLSConfigSourceFromCertificate(newBenchCertificate(), log.New(io.Discard, "", 0))
	cfg, err := source.GetClientConfig(benchBaseConfig())
	if err != nil {
		b.Fatal(err)
	}

	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = cfg.GetClientConfig()
		}
	})

	b.Run("parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_ = cfg.GetClientConfig()
			}
		})
	})
}
