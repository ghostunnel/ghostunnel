package connectproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// mockDialer is a simple proxy.Dialer that dials directly.
type mockDialer struct{}

func (d *mockDialer) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, 2*time.Second)
}

// failDialer always fails to dial.
type failDialer struct{}

func (d *failDialer) Dial(network, addr string) (net.Conn, error) {
	return nil, fmt.Errorf("dial refused")
}

// contextDialer implements proxy.ContextDialer to test that code path.
type contextDialer struct{}

func (d *contextDialer) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, 2*time.Second)
}

func (d *contextDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var dd net.Dialer
	return dd.DialContext(ctx, network, addr)
}

func TestConnectProxyDefaultPortHTTP(t *testing.T) {
	u, _ := url.Parse("http://proxy.example.com")
	dialer, err := ConnectProxy(u, &mockDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy returned error: %v", err)
	}

	d := dialer.(*httpConnectDialer)
	if d.proxyPort != "8080" {
		t.Errorf("expected default HTTP port 8080, got %s", d.proxyPort)
	}
	if d.proxyHost != "proxy.example.com" {
		t.Errorf("expected host proxy.example.com, got %s", d.proxyHost)
	}
}

func TestConnectProxyDefaultPortHTTPS(t *testing.T) {
	u, _ := url.Parse("https://proxy.example.com")
	dialer, err := ConnectProxy(u, &mockDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy returned error: %v", err)
	}

	d := dialer.(*httpConnectDialer)
	if d.proxyPort != "443" {
		t.Errorf("expected default HTTPS port 443, got %s", d.proxyPort)
	}
}

func TestConnectProxyExplicitPort(t *testing.T) {
	u, _ := url.Parse("http://proxy.example.com:3128")
	dialer, err := ConnectProxy(u, &mockDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy returned error: %v", err)
	}

	d := dialer.(*httpConnectDialer)
	if d.proxyPort != "3128" {
		t.Errorf("expected port 3128, got %s", d.proxyPort)
	}
}

func TestDialRejectsNonTCP(t *testing.T) {
	u, _ := url.Parse("http://proxy.example.com:8080")
	dialer, _ := ConnectProxy(u, &mockDialer{})

	_, err := dialer.Dial("udp", "target:80")
	if err == nil {
		t.Fatal("expected error for non-tcp network")
	}
}

func TestDialProxyFailure(t *testing.T) {
	u, _ := url.Parse("http://proxy.example.com:8080")
	dialer, _ := ConnectProxy(u, &failDialer{})

	_, err := dialer.Dial("tcp", "target:80")
	if err == nil {
		t.Fatal("expected error when proxy dial fails")
	}
}

// startSimpleMockProxy starts a proxy that reads the raw CONNECT request
// and responds with the given status code.
func startSimpleMockProxy(t *testing.T, statusCode int) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read until we see the end of HTTP headers
				buf := make([]byte, 4096)
				c.Read(buf)

				resp := fmt.Sprintf("HTTP/1.1 %d %s\r\n\r\n", statusCode, http.StatusText(statusCode))
				c.Write([]byte(resp))

				if statusCode == http.StatusOK {
					io.Copy(c, c)
				}
			}(conn)
		}
	}()

	return ln.Addr().String(), func() { ln.Close() }
}

func TestDialSuccessful(t *testing.T) {
	proxyAddr, cleanup := startSimpleMockProxy(t, http.StatusOK)
	defer cleanup()

	host, port, _ := net.SplitHostPort(proxyAddr)
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	dialer, err := ConnectProxy(u, &mockDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy error: %v", err)
	}

	conn, err := dialer.Dial("tcp", "target.example.com:443")
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	conn.Close()
}

func TestDialProxyRejects(t *testing.T) {
	proxyAddr, cleanup := startSimpleMockProxy(t, http.StatusForbidden)
	defer cleanup()

	host, port, _ := net.SplitHostPort(proxyAddr)
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	dialer, err := ConnectProxy(u, &mockDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy error: %v", err)
	}

	_, err = dialer.Dial("tcp", "target.example.com:443")
	if err == nil {
		t.Fatal("expected error when proxy returns 403")
	}
}

func TestDialContextWithContextDialer(t *testing.T) {
	proxyAddr, cleanup := startSimpleMockProxy(t, http.StatusOK)
	defer cleanup()

	host, port, _ := net.SplitHostPort(proxyAddr)
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	dialer, err := ConnectProxy(u, &contextDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy error: %v", err)
	}

	cd := dialer.(proxy.ContextDialer)
	conn, err := cd.DialContext(context.Background(), "tcp", "target.example.com:443")
	if err != nil {
		t.Fatalf("DialContext error: %v", err)
	}
	conn.Close()
}

func TestDialContextCancelled(t *testing.T) {
	// Start a proxy that delays, so cancellation can take effect
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Hold the connection open without responding
			go func(c net.Conn) {
				time.Sleep(2 * time.Second)
				c.Close()
			}(conn)
		}
	}()

	host, port, _ := net.SplitHostPort(ln.Addr().String())
	u := &url.URL{Scheme: "http", Host: net.JoinHostPort(host, port)}
	dialer, err := ConnectProxy(u, &contextDialer{})
	if err != nil {
		t.Fatalf("ConnectProxy error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cd := dialer.(proxy.ContextDialer)
	_, err = cd.DialContext(ctx, "tcp", "target.example.com:443")
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}

func TestConnectProxyImplementsInterfaces(t *testing.T) {
	u, _ := url.Parse("http://proxy.example.com:8080")
	dialer, _ := ConnectProxy(u, &mockDialer{})

	if _, ok := dialer.(proxy.Dialer); !ok {
		t.Error("should implement proxy.Dialer")
	}
	if _, ok := dialer.(proxy.ContextDialer); !ok {
		t.Error("should implement proxy.ContextDialer")
	}
}
