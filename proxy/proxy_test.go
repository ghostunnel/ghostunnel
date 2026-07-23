/*-
 * Copyright 2018 Square Inc.
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
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testLogger struct{}

func (t *testLogger) Printf(format string, v ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
}

type failingListener struct{}

func (m *failingListener) Accept() (net.Conn, error) { return nil, errors.New("failure for test") }
func (m *failingListener) Close() error              { return nil }
func (m *failingListener) Addr() net.Addr            { return nil }

func proxyForTest(listener net.Listener, dialer DialFunc) *Proxy {
	return New(listener, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff, nil)
}

func proxyForTestWithProxyProtocol(listener net.Listener, dialer DialFunc) *Proxy {
	return New(listener, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolConn, nil)
}

// Counter readers for tests that exercise New(nil), which records to the
// package-level defaultMetrics/defaultRegistry. Prometheus counters are
// monotonic and cannot be reset, so these tests assert on before/after deltas.
func errorCount() int64       { v, _ := defaultRegistry.SingleValue("accept.error"); return v }
func successCount() int64     { v, _ := defaultRegistry.SingleValue("accept.success"); return v }
func connTimeoutCount() int64 { v, _ := defaultRegistry.SingleValue("conn.timeout"); return v }
func connErrorCount() int64   { v, _ := defaultRegistry.SingleValue("conn.error"); return v }

func TestAbortedConnection(t *testing.T) {
	p := proxyForTest(&failingListener{}, nil)

	// Run proxy -- accept will always fail
	go p.Accept()
	defer p.Shutdown()

	before := errorCount()
	for range 10 {
		if errorCount() > before {
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Error("expected proxy to report errors, but got none")
}

// countingFailingListener returns errors on Accept and tracks how many times
// Accept was called, enabling assertions about the rate at which the accept
// loop retries under persistent errors.
type countingFailingListener struct {
	mu     sync.Mutex
	calls  int
	closed chan struct{}
	once   sync.Once
}

func newCountingFailingListener() *countingFailingListener {
	return &countingFailingListener{closed: make(chan struct{})}
}

func (l *countingFailingListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.calls++
	l.mu.Unlock()
	// If closed, unblock callers — but we still return an error so the
	// accept loop sees the error path. The proxy's Shutdown cancels the
	// context, which is what stops the loop.
	select {
	case <-l.closed:
		return nil, errors.New("listener closed")
	default:
	}
	return nil, errors.New("failure for test")
}

func (l *countingFailingListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *countingFailingListener) Addr() net.Addr { return nil }

func (l *countingFailingListener) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}

// TestAcceptErrorBackoff verifies that the accept loop applies an
// exponential backoff on persistent Accept errors instead of spinning
// at 100% CPU. Mirrors net/http.Server.Serve behavior: starts at ~5ms,
// doubles up to ~1s.
func TestAcceptErrorBackoff(t *testing.T) {
	ln := newCountingFailingListener()
	p := proxyForTest(ln, nil)

	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()

	// Without backoff, the loop would call Accept many thousands of times in
	// 200ms. With backoff starting at 5ms and doubling to 1s, the number of
	// calls is bounded: roughly 5 + 5 + 10 + 20 + 40 + 80 ms = ~160ms after
	// 6 errors, so within 200ms we should see at most ~7 calls.
	time.Sleep(200 * time.Millisecond)

	calls := ln.count()
	if calls < 2 {
		t.Errorf("expected accept loop to retry at least twice in 200ms, got %d", calls)
	}
	if calls > 25 {
		t.Errorf("expected accept loop to be rate-limited by backoff, got %d calls in 200ms", calls)
	}
}

// TestAcceptErrorBackoffShutdownInterrupts verifies that Shutdown promptly
// interrupts the backoff sleep rather than waiting for it to elapse.
func TestAcceptErrorBackoffShutdownInterrupts(t *testing.T) {
	ln := newCountingFailingListener()
	p := proxyForTest(ln, nil)

	go p.Accept()

	// Let the loop accumulate enough errors to reach the max backoff (1s).
	// 5+10+20+40+80+160+320+640+1000 = ~2.3s, so 1500ms is plenty to ensure
	// we're sleeping in a long backoff window.
	time.Sleep(1500 * time.Millisecond)

	start := time.Now()
	p.Shutdown()
	p.Wait()
	elapsed := time.Since(start)

	// Shutdown should not have to wait for the full 1s backoff sleep to
	// elapse. Allow some slack for scheduler jitter, but it must be well
	// under the max backoff.
	if elapsed > 500*time.Millisecond {
		t.Errorf("Shutdown took %v, expected backoff sleep to be interrupted promptly", elapsed)
	}
}

// TestAcceptErrorLoggedConditionally verifies that persistent Accept errors
// are surfaced via logConditional with the LogConnectionErrors flag.
func TestAcceptErrorLogged(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	logger := &callbackLogger{callback: func(format string, v ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, v...))
	}}

	ln := newCountingFailingListener()
	p := New(ln, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, nil, logger, LogConnectionErrors, ProxyProtocolOff, nil)

	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()

	// Wait for at least one accept error to be logged.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(logged)
		mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) == 0 {
		t.Fatal("expected accept error to be logged via LogConnectionErrors")
	}
	if !strings.Contains(logged[0], "error accepting connection") {
		t.Errorf("expected log message to mention accept error, got: %q", logged[0])
	}
}

// TestAcceptErrorNotLoggedWhenFlagDisabled verifies that with the
// LogConnectionErrors flag disabled, accept errors are not logged.
func TestAcceptErrorNotLoggedWhenFlagDisabled(t *testing.T) {
	var mu sync.Mutex
	var logged []string
	logger := &callbackLogger{callback: func(format string, v ...any) {
		mu.Lock()
		defer mu.Unlock()
		logged = append(logged, fmt.Sprintf(format, v...))
	}}

	ln := newCountingFailingListener()
	// loggerFlags = 0 (no flags set) -- accept errors must not be logged.
	p := New(ln, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, nil, logger, 0, ProxyProtocolOff, nil)

	go p.Accept()
	defer func() {
		p.Shutdown()
		p.Wait()
	}()

	// Wait for several accept errors to occur.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if ln.count() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(logged) > 0 {
		t.Errorf("expected no logs when LogConnectionErrors flag is disabled, got %d: %v", len(logged), logged)
	}
}

func TestMaxConcurrentConns(t *testing.T) {
	// Incoming listener
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")
	defer incoming.Close()

	// Target listener
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")
	defer target.Close()

	dialer := func(_ context.Context) (net.Conn, error) {
		return net.Dial("tcp", target.Addr().String())
	}

	// Start accept loop
	p := proxyForTest(incoming, dialer)
	go p.Accept()
	defer p.Shutdown()

	// Proxy multiple connections
	// First conn
	src0, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")

	dst0, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")
	defer dst0.Close()

	// Second conn (while first conn still open)
	src1, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")
	defer src1.Close()

	// Set deadline for accept
	err = target.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
	assert.Nil(t, err, "should be able to set deadline")

	_, err = target.Accept()
	assert.NotNil(t, err, "should not be able to receive second conn")

	src0.Close()
	dst0.Close()
	src1.Close()
	p.Shutdown()
	p.Wait()
}

func TestMultipleShutdownCalls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	p := proxyForTest(ln, nil)

	// Should not panic
	p.Shutdown()
	p.Shutdown()
	p.Shutdown()
	p.Wait()
}

func TestConcurrentShutdownCalls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	p := proxyForTest(ln, nil)

	// Without the sync.Once guard, two goroutines can both pass the
	// context.Err() check and both call handlers.Done(), driving the
	// WaitGroup counter negative and panicking.
	const n = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			p.Shutdown()
		}()
	}
	close(start)
	wg.Wait()

	p.Wait() // should not panic; proxy fully drained
}

func TestProxySuccess(t *testing.T) {
	// Incoming listener
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")
	defer incoming.Close()

	// Target listener
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")
	defer target.Close()

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}

	// Start accept loop
	p := proxyForTest(incoming, dialer)
	go p.Accept()
	defer p.Shutdown()

	// Proxy a connection
	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")
	defer src.Close()

	dst, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")
	defer dst.Close()

	_, _ = src.Write([]byte("A"))

	received := make([]byte, 1)
	for {
		n, err := dst.Read(received)
		if !errors.Is(err, io.EOF) {
			assert.Nil(t, err, "should be able to receive data from connection on target")
		}
		if n == 1 {
			break
		}
	}

	if !bytes.Equal([]byte("A"), received) {
		t.Error("got wrong data from connection on target")
	}

	dst.Close()
	src.Close()
	p.Shutdown()
	p.Wait()
}

func TestProxyProtocolSuccess(t *testing.T) {
	// Incoming listener
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	// Target listener
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}

	// Start accept loop
	p := proxyForTestWithProxyProtocol(incoming, dialer)
	go p.Accept()
	defer p.Shutdown()

	// Proxy a connection
	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")

	dst, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")

	header, err := proxyproto.Read(bufio.NewReaderSize(dst, 12))
	assert.Nil(t, err, "should be able to read header")
	assert.Equal(t, header.Version, uint8(2))
	assert.Equal(t, header.Command, proxyproto.PROXY)
	assert.Equal(t, header.TransportProtocol, proxyproto.TCPv4)
	assert.Equal(t, header.SourceAddr.(*net.TCPAddr).IP, net.ParseIP("127.0.0.1").To4())
	assert.Equal(t, header.DestinationAddr.(*net.TCPAddr).IP, net.ParseIP("127.0.0.1").To4())
	assert.Equal(t, header.SourceAddr.(*net.TCPAddr).Port, src.LocalAddr().(*net.TCPAddr).Port)
	assert.Equal(t, header.DestinationAddr.(*net.TCPAddr).Port, incoming.Addr().(*net.TCPAddr).Port)

	_, _ = src.Write([]byte("A"))

	received := make([]byte, 1)
	for {
		n, err := dst.Read(received)
		if !errors.Is(err, io.EOF) {
			assert.Nil(t, err, "should be able to receive data from connection on target")
		}
		if n == 1 {
			break
		}
	}

	if !bytes.Equal([]byte("A"), received) {
		t.Error("got wrong data from connection on target")
	}

	p.Shutdown()
	dst.Close()
	src.Close()
	p.Wait()
}

func TestProxyProtocolSuccessIPv6(t *testing.T) {
	// PROXY v2 header for an IPv6 client must report TransportProtocol=TCPv6.
	incoming, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available")
	}
	defer incoming.Close()

	target, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 not available for backend")
	}
	defer target.Close()

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp6", target.Addr().String())
	}

	p := proxyForTestWithProxyProtocol(incoming, dialer)
	go p.Accept()
	defer p.Shutdown()

	src, err := net.Dial("tcp6", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy over IPv6")

	dst, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")

	header, err := proxyproto.Read(bufio.NewReaderSize(dst, 512))
	assert.Nil(t, err, "should be able to read header")
	assert.Equal(t, uint8(2), header.Version)
	assert.Equal(t, proxyproto.PROXY, header.Command)
	// Core assertion: transport protocol byte reports TCPv6.
	assert.Equal(t, proxyproto.TCPv6, header.TransportProtocol,
		"PROXY header must report TCPv6 for an IPv6 client")
	// Source/dest addresses should be IPv6 loopback.
	assert.True(t, header.SourceAddr.(*net.TCPAddr).IP.Equal(net.IPv6loopback),
		"source address must be ::1")
	assert.True(t, header.DestinationAddr.(*net.TCPAddr).IP.Equal(net.IPv6loopback),
		"destination address must be ::1")
	assert.Equal(t, src.LocalAddr().(*net.TCPAddr).Port, header.SourceAddr.(*net.TCPAddr).Port)
	assert.Equal(t, incoming.Addr().(*net.TCPAddr).Port, header.DestinationAddr.(*net.TCPAddr).Port)

	p.Shutdown()
	dst.Close()
	src.Close()
	p.Wait()
}

func TestBackendDialError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	dialer := func(ctx context.Context) (net.Conn, error) {
		return nil, errors.New("failure for test")
	}

	// Regression: dial failure must be recorded as an error, not silently
	// dropped (accept.total would otherwise diverge from success+error).
	// Prometheus counters are monotonic, so assert on before/after deltas.
	errBefore := errorCount()
	successBefore := successCount()

	p := proxyForTest(ln, dialer)
	go p.Accept()
	defer p.Shutdown()

	// Open a connection, should get reset once backend dial fails
	src, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")
	defer src.Close()

	failed := false
	for range 100 {
		_, err := src.Write([]byte("A"))
		if err != nil {
			failed = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !failed {
		t.Error("proxied connection never failed even though backend is dead?")
	}

	p.Shutdown()
	p.Wait()

	// After Wait() the handler goroutine has drained, so counters are settled.
	assert.Equal(t, int64(1), errorCount()-errBefore, "backend dial failure must increment accept.error")
	assert.Equal(t, int64(0), successCount()-successBefore, "backend dial failure must not increment accept.success")
}

func TestCopyData(t *testing.T) {
	size := 16 /* bytes */
	proxy := proxyForTest(nil, nil)

	srcIn, srcOut := net.Pipe()
	dstIn, dstOut := net.Pipe()
	defer func() {
		srcIn.Close()
		srcOut.Close()
		dstIn.Close()
		dstOut.Close()
	}()

	go func() {
		proxy.copyData(dstIn, srcOut, proxy.newPairWatchdog(dstIn, srcOut))
	}()

	input := make([]byte, size)
	for i := range size {
		input[i] = byte(i)
	}

	_, _ = srcIn.Write(input)
	srcIn.Close()

	output := make([]byte, size)
	n, err := dstOut.Read(output)
	if n != size {
		t.Fatalf("expected %d bytes, got %d instead", size, n)
	}
	if err != nil && !errors.Is(err, io.EOF) && !isClosedConnectionError(err) {
		t.Fatalf("got unexpected error: %v", err)
	}
	if !bytes.Equal(input, output) {
		t.Fatalf("input and output were different after copy")
	}
}

// mockNetError implements net.Error for testing isTimeoutError
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("test error"),
			expected: false,
		},
		{
			name:     "net.Error with timeout=true",
			err:      &mockNetError{timeout: true, msg: "timeout error"},
			expected: true,
		},
		{
			name:     "net.Error with timeout=false",
			err:      &mockNetError{timeout: false, msg: "non-timeout error"},
			expected: false,
		},
		{
			name:     "context.DeadlineExceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name:     "context.Canceled",
			err:      context.Canceled,
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isTimeoutError(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsClosedConnectionError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "regular error",
			err:      errors.New("test error"),
			expected: false,
		},
		{
			name:     "closed pipe error",
			err:      errors.New("read/write on closed pipe"),
			expected: true,
		},
		{
			name:     "raw net.ErrClosed",
			err:      net.ErrClosed,
			expected: true,
		},
		{
			name: "net.OpError wrapping net.ErrClosed",
			err: &net.OpError{
				Op:  "read",
				Err: net.ErrClosed,
			},
			expected: true,
		},
		{name: "net.OpError read ECONNRESET", err: &net.OpError{Op: "read", Err: syscall.ECONNRESET}, expected: true},
		{name: "net.OpError write EPIPE", err: &net.OpError{Op: "write", Err: syscall.EPIPE}, expected: true},
		{name: "raw ECONNRESET", err: syscall.ECONNRESET, expected: true},
		{name: "raw EPIPE", err: syscall.EPIPE, expected: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isClosedConnectionError(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestIsClosedConnectionErrorNil(t *testing.T) {
	// A nil error must be classified without dereferencing (err.Error() would
	// panic on nil), so callers can pass a copy result unconditionally.
	var result bool
	assert.NotPanics(t, func() {
		result = isClosedConnectionError(nil)
	})
	assert.False(t, result)
}

// mockConn is a minimal net.Conn implementation that is neither TCP nor Unix
type mockConn struct {
	closed bool
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestCloseReadNonTCPConnection(t *testing.T) {
	conn := &mockConn{}
	closeRead(conn)
	assert.True(t, conn.closed, "non-TCP/Unix conn should be closed via Close()")
}

func TestCloseWriteNonTCPConnection(t *testing.T) {
	conn := &mockConn{}
	closeWrite(conn)
	assert.True(t, conn.closed, "non-TCP/Unix conn should be closed via Close()")
}

func TestCloseReadTCPConnection(t *testing.T) {
	// Create a TCP connection pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	// closeRead should not panic and should work on TCP
	closeRead(conn)
}

func TestCloseWriteTCPConnection(t *testing.T) {
	// Create a TCP connection pair
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			time.Sleep(100 * time.Millisecond)
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	// closeWrite should not panic and should work on TCP
	closeWrite(conn)
}

// unixSocketPair sets up a connected pair of *net.UnixConn endpoints over a
// stream socket in a temp dir. It returns the client (dial) side and the
// server (accept) side, plus a cleanup func.
func unixSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn, func()) {
	t.Helper()
	dir := t.TempDir()
	addr := &net.UnixAddr{Name: dir + "/sock", Net: "unix"}

	ln, err := net.ListenUnix("unix", addr)
	assert.Nil(t, err, "should be able to listen on unix socket")

	type acceptResult struct {
		conn *net.UnixConn
		err  error
	}
	acceptC := make(chan acceptResult, 1)
	go func() {
		c, err := ln.AcceptUnix()
		acceptC <- acceptResult{c, err}
	}()

	client, err := net.DialUnix("unix", nil, addr)
	assert.Nil(t, err, "should be able to dial unix socket")

	res := <-acceptC
	assert.Nil(t, res.err, "should accept unix connection")

	cleanup := func() {
		_ = client.Close()
		if res.conn != nil {
			_ = res.conn.Close()
		}
		_ = ln.Close()
	}
	return client, res.conn, cleanup
}

func TestCloseReadUnixConnection(t *testing.T) {
	client, server, cleanup := unixSocketPair(t)
	defer cleanup()

	// closeRead on *net.UnixConn must call CloseRead, not Close: writes still work.
	closeRead(client)

	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = server.SetDeadline(time.Now().Add(2 * time.Second))

	n, err := client.Write([]byte("hi"))
	assert.Nil(t, err, "client must still be able to write after closeRead")
	assert.Equal(t, 2, n)

	buf := make([]byte, 2)
	got, err := io.ReadFull(server, buf)
	assert.Nil(t, err)
	assert.Equal(t, 2, got)
	assert.Equal(t, []byte("hi"), buf)
}

func TestCloseWriteUnixConnection(t *testing.T) {
	client, server, cleanup := unixSocketPair(t)
	defer cleanup()

	// closeWrite on *net.UnixConn must call CloseWrite, not Close: reads still
	// work on the client side. (A plain Close would tear down both halves, so
	// we verify the read half still functions to confirm we hit the right branch.)
	closeWrite(client)

	go func() {
		_, _ = server.Write([]byte("hello"))
		_ = server.CloseWrite()
	}()

	_ = server.SetDeadline(time.Now().Add(2 * time.Second))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	buf := make([]byte, 5)
	n, err := io.ReadFull(client, buf)
	assert.Nil(t, err, "client must still be able to read after closeWrite")
	assert.Equal(t, 5, n)
	assert.Equal(t, []byte("hello"), buf)

	one := make([]byte, 1)
	_, err = server.Read(one)
	assert.Equal(t, io.EOF, err, "server must observe EOF after client closeWrite")
}

// discardConn accepts writes silently, blocks on Read until Close releases it.
type discardConn struct {
	mockConn
	closed chan struct{}
	once   sync.Once
}

func newDiscardConn() *discardConn {
	return &discardConn{closed: make(chan struct{})}
}

func (d *discardConn) Read(_ []byte) (int, error) {
	<-d.closed
	return 0, io.EOF
}
func (d *discardConn) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardConn) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

// readErrConn returns any optional payload bytes first, then err on every Read.
type readErrConn struct {
	mockConn
	payload []byte
	err     error
	pos     int
}

func (r *readErrConn) Read(p []byte) (int, error) {
	if r.pos < len(r.payload) {
		n := copy(p, r.payload[r.pos:])
		r.pos += n
		return n, nil
	}
	return 0, r.err
}

// fakeTimeoutError is a net.Error with Timeout()==true; not a closed-conn error.
type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout (simulated)" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return false }

func TestCopyDataErrorClassification(t *testing.T) {
	type logEntry struct {
		format string
		args   []any
	}

	newCapturingProxy := func(flags int) (*Proxy, *[]logEntry) {
		var logs []logEntry
		lg := &callbackLogger{callback: func(format string, v ...any) {
			logs = append(logs, logEntry{format: format, args: v})
		}}
		p := New(nil, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second}, 0, nil, lg, flags, ProxyProtocolOff, nil)
		return p, &logs
	}

	countCopyErrorLogs := func(logs []logEntry) int {
		n := 0
		for _, e := range logs {
			if strings.HasPrefix(e.format, "error during copy:") {
				n++
			}
		}
		return n
	}

	t.Run("real I/O error logged and counted when LogConnectionErrors set", func(t *testing.T) {
		src := &readErrConn{
			payload: []byte("hello"),
			err:     errors.New("synthetic disk gone bad"),
		}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnectionErrors)
		beforeTimeout := connTimeoutCount()
		beforeErr := connErrorCount()
		written := p.copyData(dst, src, p.newPairWatchdog(dst, src))
		afterTimeout := connTimeoutCount()
		afterErr := connErrorCount()

		assert.Equal(t, int64(5), written, "payload should be copied before the error")
		assert.Equal(t, 1, countCopyErrorLogs(*logs), "real I/O error must be logged once")
		assert.Equal(t, beforeTimeout, afterTimeout, "non-timeout error must not bump connTimeoutCounter")
		assert.Equal(t, int64(1), afterErr-beforeErr, "real I/O error must increment conn.error")
	})

	t.Run("real I/O error suppressed when LogConnectionErrors cleared", func(t *testing.T) {
		src := &readErrConn{err: errors.New("synthetic disk gone bad")}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnections)
		before := connErrorCount()
		_ = p.copyData(dst, src, p.newPairWatchdog(dst, src))

		assert.Equal(t, 0, countCopyErrorLogs(*logs),
			"copy errors must be silent without LogConnectionErrors")
		assert.Equal(t, int64(1), connErrorCount()-before,
			"conn.error must be incremented even when logging is suppressed")
	})

	t.Run("timeout-shaped error is classified as a real copy error", func(t *testing.T) {
		// The watchdog, not copyData, owns timeout counting and logging. It reaps
		// by closing the conns, which surfaces to copyData as net.ErrClosed. A
		// timeout-shaped error therefore never reaches copyData in production.
		// If one somehow did, copyData treats it like any other non-closed
		// error. It is counted as conn.error and logged as "error during copy",
		// NOT as a timeout. Timeout counting is covered end-to-end by
		// TestIdleTimeoutReapLoggedNotErrored and the max-conn-lifetime tests.
		src := &readErrConn{err: fakeTimeoutError{}}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogEverything)
		beforeTimeout := connTimeoutCount()
		beforeErr := connErrorCount()
		_ = p.copyData(dst, src, p.newPairWatchdog(dst, src))

		assert.Equal(t, beforeTimeout, connTimeoutCount(),
			"copyData must not bump connTimeoutCounter; only the watchdog counts timeouts")
		assert.Equal(t, int64(1), connErrorCount()-beforeErr,
			"a timeout-shaped error reaching copyData is counted as conn.error")
		assert.Equal(t, 1, countCopyErrorLogs(*logs),
			"a timeout-shaped error reaching copyData is logged as 'error during copy'")
	})

	t.Run("closed-connection error is silently suppressed", func(t *testing.T) {
		src := &readErrConn{err: errors.New("io: read/write on closed pipe")}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnectionErrors)
		before := connTimeoutCount()
		_ = p.copyData(dst, src, p.newPairWatchdog(dst, src))
		after := connTimeoutCount()

		assert.Equal(t, 0, countCopyErrorLogs(*logs),
			"closed-connection errors must be silently suppressed by copyData")
		assert.Equal(t, before, after,
			"closed-connection errors must not affect connTimeoutCounter")
	})
}

func TestForceHandshakeNonTLSConn(t *testing.T) {
	// Create a regular TCP connection (non-TLS)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer listener.Close()

	go func() {
		conn, _ := listener.Accept()
		if conn != nil {
			conn.Close()
		}
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	// forceHandshake should be a no-op for non-TLS connections
	ctx := context.Background()
	err = forceHandshake(ctx, conn, defaultMetrics)
	assert.Nil(t, err, "forceHandshake should succeed for non-TLS conn")
}

func TestIsACMEChallengeConn(t *testing.T) {
	// Non-TLS conn is never an ACME challenge.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	assert.False(t, isACMEChallengeConn(a), "plain net.Conn must not be classified as ACME")

	// TLS conn with no negotiated protocol is not an ACME challenge.
	tlsConn := tls.Client(a, &tls.Config{InsecureSkipVerify: true})
	assert.False(t, isACMEChallengeConn(tlsConn), "TLS conn with empty NegotiatedProtocol must not be classified as ACME")
}

func TestACMEChallengeNotForwardedToBackend(t *testing.T) {
	// End-to-end: a TLS-ALPN-01 probe (ALPN=acme-tls/1, no client cert)
	// against a proxy whose listener config requires mTLS but relaxes for
	// acme-tls/1 must complete the TLS handshake AND must NOT result in a
	// backend dial. This is what prevents the renewal exemption from
	// becoming an mTLS bypass into the backend.
	cert, _ := selfSignedCert(t)

	clientCAs := x509.NewCertPool()
	// Empty pool — no real client cert would ever satisfy mTLS, which is
	// what we want: the only way through is the acme-tls/1 exemption.

	baseConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		NextProtos:   []string{"acme-tls/1"},
		MinVersion:   tls.VersionTLS12,
	}
	baseConfig.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		if len(chi.SupportedProtos) == 1 && chi.SupportedProtos[0] == "acme-tls/1" {
			c := baseConfig.Clone()
			c.ClientAuth = tls.NoClientCert
			c.ClientCAs = nil
			c.NextProtos = []string{"acme-tls/1"}
			c.SessionTicketsDisabled = true
			c.ClientSessionCache = nil
			return c, nil
		}
		return nil, nil
	}

	rawIncoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	incoming := tls.NewListener(rawIncoming, baseConfig)
	defer incoming.Close()

	// Backend listener: we assert it is NEVER reached during this test.
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer target.Close()

	var backendHits int32
	backendDone := make(chan struct{})
	go func() {
		defer close(backendDone)
		conn, err := target.Accept()
		if err != nil {
			return
		}
		atomic.AddInt32(&backendHits, 1)
		conn.Close()
	}()

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}

	p := proxyForTest(incoming, dialer)
	go p.Accept()
	defer p.Shutdown()

	// Drive an ACME validator-shaped handshake: only acme-tls/1 in ALPN,
	// no client certificate, skip server verification (self-signed).
	clientConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"acme-tls/1"},
		MinVersion:         tls.VersionTLS12,
	}
	tlsClient, err := tls.Dial("tcp", incoming.Addr().String(), clientConfig)
	assert.Nil(t, err, "TLS-ALPN-01 probe handshake must succeed")
	if err == nil {
		assert.Equal(t, "acme-tls/1", tlsClient.ConnectionState().NegotiatedProtocol,
			"server must negotiate acme-tls/1")
		tlsClient.Close()
	}

	// Give the proxy a moment to (incorrectly) dial the backend if it would.
	select {
	case <-backendDone:
		// Backend Accept returned — only legitimate if the listener was
		// closed below, not because a connection arrived.
	case <-time.After(500 * time.Millisecond):
	}

	assert.Equal(t, int32(0), atomic.LoadInt32(&backendHits),
		"backend MUST NOT receive any connection from an ACME TLS-ALPN-01 probe")

	// Sanity check: a normal (non-ACME) client without a client cert must
	// still be rejected at the handshake — i.e. mTLS for the real path is
	// not weakened by the exemption.
	plainConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS12,
	}
	plain, err := tls.Dial("tcp", incoming.Addr().String(), plainConfig)
	if err == nil {
		// Handshake might appear to succeed from client side until first I/O
		// in some TLS versions; force it.
		err = plain.Handshake()
		plain.Close()
	}
	assert.Error(t, err, "non-ACME client without cert must fail mTLS handshake")
	assert.Equal(t, int32(0), atomic.LoadInt32(&backendHits),
		"backend MUST still not be reached after rejected mTLS handshake")
}

func TestLogConnectionMessageDisabled(t *testing.T) {
	// Test with LogConnections disabled
	p := New(nil, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second}, 0, nil, &testLogger{}, 0, ProxyProtocolOff, nil)

	// Create pipe connections
	src, dst := net.Pipe()
	defer src.Close()
	defer dst.Close()

	// Should not panic even with logging disabled
	p.logConnectionMessage("test", src, dst, 0, 0, time.Time{})
}

func TestLogConditional(t *testing.T) {
	logged := false
	logger := &callbackLogger{callback: func(format string, v ...any) {
		logged = true
	}}

	// Test with flag enabled
	p := New(nil, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second}, 0, nil, logger, LogConnectionErrors, ProxyProtocolOff, nil)
	p.logConditional(LogConnectionErrors, "test message")
	assert.True(t, logged, "should log when flag is enabled")

	// Test with flag disabled
	logged = false
	p.logConditional(LogHandshakeErrors, "test message")
	assert.False(t, logged, "should not log when flag is disabled")
}

type callbackLogger struct {
	callback func(format string, v ...any)
}

func (c *callbackLogger) Printf(format string, v ...any) {
	c.callback(format, v...)
}

func TestTransportProtocol(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		assert.Nil(t, err)
		defer ln.Close()

		go func() {
			c, _ := ln.Accept()
			if c != nil {
				c.Close()
			}
		}()

		conn, err := net.Dial("tcp4", ln.Addr().String())
		assert.Nil(t, err)
		defer conn.Close()

		assert.Equal(t, proxyproto.TCPv4, transportProtocol(conn))
	})

	t.Run("IPv6", func(t *testing.T) {
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skip("IPv6 not available")
		}
		defer ln.Close()

		go func() {
			c, _ := ln.Accept()
			if c != nil {
				c.Close()
			}
		}()

		conn, err := net.Dial("tcp6", ln.Addr().String())
		assert.Nil(t, err)
		defer conn.Close()

		assert.Equal(t, proxyproto.TCPv6, transportProtocol(conn))
	})

	t.Run("Unix", func(t *testing.T) {
		dir := t.TempDir()
		sockPath := filepath.Join(dir, "s.sock")
		ln, err := net.Listen("unix", sockPath)
		assert.Nil(t, err)
		defer ln.Close()

		go func() {
			c, _ := ln.Accept()
			if c != nil {
				c.Close()
			}
		}()

		conn, err := net.Dial("unix", sockPath)
		assert.Nil(t, err)
		defer conn.Close()

		assert.Equal(t, proxyproto.UnixStream, transportProtocol(conn))

		// Regression check: when the listener is unix,
		// proxyProtoHeader(...).WriteTo previously failed with
		// proxyproto.ErrInvalidAddress because TransportProtocol was
		// TCPv4 but SourceAddr/DestinationAddr were *net.UnixAddr, causing
		// every proxied connection to be dropped before any bytes were
		// written to the backend.
		h, err := proxyProtoHeader(conn, nil, ProxyProtocolConn)
		assert.NoError(t, err)
		var buf bytes.Buffer
		n, err := h.WriteTo(&buf)
		assert.Nil(t, err, "WriteTo must not return ErrInvalidAddress for unix listener")
		assert.True(t, n > 0, "WriteTo must write the PROXY header bytes")
	})

	t.Run("unknown address fallback", func(t *testing.T) {
		// RemoteAddr returns *net.IPAddr, which is neither *net.TCPAddr
		// nor *net.UnixAddr; we fall back to UNSPEC rather than misreporting
		// the transport protocol.
		conn := &mockConn{}
		assert.Equal(t, proxyproto.UNSPEC, transportProtocol(conn))
	})
}

// selfSignedCert creates a self-signed certificate for testing.
func selfSignedCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         "test-cn",
			OrganizationalUnit: []string{"test-ou"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.Nil(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.Nil(t, err)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, parsedCert
}

// emptyCNCert creates a self-signed certificate with an empty CommonName.
func emptyCNCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.Nil(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"test-ou-no-cn"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.Nil(t, err)

	parsedCert, err := x509.ParseCertificate(certDER)
	assert.Nil(t, err)
	assert.Equal(t, "", parsedCert.Subject.CommonName, "test setup: parsed cert must have empty CN")

	return parsedCert
}

func TestBuildSSLTLV(t *testing.T) {
	t.Run("without client cert", func(t *testing.T) {
		state := &tls.ConnectionState{
			Version:     tls.VersionTLS13,
			CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		}

		tlv, err := buildSSLTLV(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)
		assert.Equal(t, proxyproto.PP2_TYPE_SSL, tlv.Type)

		// Parse 5-byte sub-header
		assert.True(t, len(tlv.Value) >= 5, "SSL TLV value must be at least 5 bytes")
		flags := tlv.Value[0]
		verify := binary.BigEndian.Uint32(tlv.Value[1:5])

		assert.Equal(t, byte(pp2ClientSSL), flags, "should only have PP2_CLIENT_SSL flag")
		assert.Equal(t, uint32(0), verify, "verify result should be 0")

		// Parse nested sub-TLVs
		subTLVs, err := proxyproto.SplitTLVs(tlv.Value[5:])
		assert.Nil(t, err)

		// Should have VERSION only, not CN/CLIENT_CERT
		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, st := range subTLVs {
			typeSet[st.Type] = st.Value
		}

		assert.Contains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_VERSION)
		assert.Equal(t, "TLS 1.3", string(typeSet[proxyproto.PP2_SUBTYPE_SSL_VERSION]))
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_CN)
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT)
	})

	t.Run("with client cert", func(t *testing.T) {
		_, parsedCert := selfSignedCert(t)

		state := &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{parsedCert},
		}

		tlv, err := buildSSLTLV(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		// Parse sub-header
		flags := tlv.Value[0]
		assert.Equal(t, byte(pp2ClientSSL|pp2ClientCertConn|pp2ClientCertSess), flags)

		// Parse nested sub-TLVs
		subTLVs, err := proxyproto.SplitTLVs(tlv.Value[5:])
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, st := range subTLVs {
			typeSet[st.Type] = st.Value
		}

		assert.Equal(t, "test-cn", string(typeSet[proxyproto.PP2_SUBTYPE_SSL_CN]))
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_KEY_ALG)
		assert.Equal(t, parsedCert.Raw, typeSet[proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT])
	})

	t.Run("TLS mode excludes client cert", func(t *testing.T) {
		_, parsedCert := selfSignedCert(t)

		state := &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{parsedCert},
		}

		tlv, err := buildSSLTLV(state, ProxyProtocolTLS)
		assert.Nil(t, err)

		// Parse sub-header: should only have PP2_CLIENT_SSL (no cert flags)
		flags := tlv.Value[0]
		assert.Equal(t, byte(pp2ClientSSL), flags, "TLS mode should not set cert flags")

		// Parse nested sub-TLVs: should have version but no cert details
		subTLVs, err := proxyproto.SplitTLVs(tlv.Value[5:])
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, st := range subTLVs {
			typeSet[st.Type] = st.Value
		}

		assert.Contains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_VERSION)
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_CN)
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT)
	})

	t.Run("with client cert empty CN", func(t *testing.T) {
		// Empty CN: omit CN sub-TLV entirely (not as an empty-value TLV).
		// DER cert sub-TLV and PP2_CLIENT_CERT_* flags must still be set.
		parsedCert := emptyCNCert(t)

		state := &tls.ConnectionState{
			Version:          tls.VersionTLS13,
			CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
			PeerCertificates: []*x509.Certificate{parsedCert},
		}

		tlv, err := buildSSLTLV(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		// Cert flags must still be set: a cert WAS presented.
		flags := tlv.Value[0]
		assert.Equal(t, byte(pp2ClientSSL|pp2ClientCertConn|pp2ClientCertSess), flags,
			"cert flags must be set even when CN is empty")

		subTLVs, err := proxyproto.SplitTLVs(tlv.Value[5:])
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, st := range subTLVs {
			typeSet[st.Type] = st.Value
		}

		// CN sub-TLV must be omitted (not present as empty bytes).
		assert.NotContains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_CN,
			"CN sub-TLV must be omitted when client cert has empty CommonName")
		// DER cert sub-TLV must still be present and match raw bytes.
		assert.Equal(t, parsedCert.Raw, typeSet[proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT],
			"DER cert sub-TLV must still be emitted when CN is empty")
		// Version sub-TLV always present.
		assert.Contains(t, typeSet, proxyproto.PP2_SUBTYPE_SSL_VERSION)
	})
}

func TestBuildTLVs(t *testing.T) {
	t.Run("with ALPN and SNI", func(t *testing.T) {
		state := &tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h2",
			ServerName:         "example.com",
		}

		tlvs, err := buildTLVs(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, tlv := range tlvs {
			typeSet[tlv.Type] = tlv.Value
		}

		assert.Equal(t, "h2", string(typeSet[proxyproto.PP2_TYPE_ALPN]))
		assert.Equal(t, "example.com", string(typeSet[proxyproto.PP2_TYPE_AUTHORITY]))
		assert.Contains(t, typeSet, proxyproto.PP2_TYPE_SSL)
	})

	t.Run("without ALPN and SNI", func(t *testing.T) {
		state := &tls.ConnectionState{
			Version:     tls.VersionTLS13,
			CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		}

		tlvs, err := buildTLVs(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, tlv := range tlvs {
			typeSet[tlv.Type] = tlv.Value
		}

		assert.NotContains(t, typeSet, proxyproto.PP2_TYPE_ALPN)
		assert.NotContains(t, typeSet, proxyproto.PP2_TYPE_AUTHORITY)
		assert.Contains(t, typeSet, proxyproto.PP2_TYPE_SSL)
	})

	t.Run("ALPN only", func(t *testing.T) {
		// NegotiatedProtocol set, SNI empty: Authority TLV must be omitted entirely.
		state := &tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h2",
		}

		tlvs, err := buildTLVs(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, tlv := range tlvs {
			typeSet[tlv.Type] = tlv.Value
		}

		assert.Equal(t, "h2", string(typeSet[proxyproto.PP2_TYPE_ALPN]),
			"ALPN TLV must carry the negotiated protocol")
		assert.NotContains(t, typeSet, proxyproto.PP2_TYPE_AUTHORITY,
			"Authority TLV must be omitted when SNI is empty")
		assert.Contains(t, typeSet, proxyproto.PP2_TYPE_SSL)
	})

	t.Run("SNI only", func(t *testing.T) {
		// ServerName set, NegotiatedProtocol empty: ALPN TLV must be omitted entirely.
		state := &tls.ConnectionState{
			Version:     tls.VersionTLS13,
			CipherSuite: tls.TLS_AES_128_GCM_SHA256,
			ServerName:  "example.com",
		}

		tlvs, err := buildTLVs(state, ProxyProtocolTLSFull)
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, tlv := range tlvs {
			typeSet[tlv.Type] = tlv.Value
		}

		assert.NotContains(t, typeSet, proxyproto.PP2_TYPE_ALPN,
			"ALPN TLV must be omitted when NegotiatedProtocol is empty")
		assert.Equal(t, "example.com", string(typeSet[proxyproto.PP2_TYPE_AUTHORITY]),
			"Authority TLV must carry the SNI")
		assert.Contains(t, typeSet, proxyproto.PP2_TYPE_SSL)
	})

	t.Run("TLS mode with client cert", func(t *testing.T) {
		_, parsedCert := selfSignedCert(t)

		state := &tls.ConnectionState{
			Version:            tls.VersionTLS13,
			CipherSuite:        tls.TLS_AES_128_GCM_SHA256,
			NegotiatedProtocol: "h2",
			ServerName:         "example.com",
			PeerCertificates:   []*x509.Certificate{parsedCert},
		}

		tlvs, err := buildTLVs(state, ProxyProtocolTLS)
		assert.Nil(t, err)

		typeSet := make(map[proxyproto.PP2Type][]byte)
		for _, tlv := range tlvs {
			typeSet[tlv.Type] = tlv.Value
		}

		// ALPN, SNI, SSL should be present
		assert.Equal(t, "h2", string(typeSet[proxyproto.PP2_TYPE_ALPN]))
		assert.Equal(t, "example.com", string(typeSet[proxyproto.PP2_TYPE_AUTHORITY]))
		assert.Contains(t, typeSet, proxyproto.PP2_TYPE_SSL)

		// SSL TLV should have version but no client cert sub-TLVs
		sslValue := typeSet[proxyproto.PP2_TYPE_SSL]
		subTLVs, err := proxyproto.SplitTLVs(sslValue[5:])
		assert.Nil(t, err)

		subTypeSet := make(map[proxyproto.PP2Type]bool)
		for _, st := range subTLVs {
			subTypeSet[st.Type] = true
		}
		assert.True(t, subTypeSet[proxyproto.PP2_SUBTYPE_SSL_VERSION])
		assert.False(t, subTypeSet[proxyproto.PP2_SUBTYPE_SSL_CN])
		assert.False(t, subTypeSet[proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT])
	})
}

func TestProxyProtoHeaderWithTLS(t *testing.T) {
	_, parsedCert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		ServerName:       "example.com",
		PeerCertificates: []*x509.Certificate{parsedCert},
	}

	h, err := proxyProtoHeader(conn, state, ProxyProtocolTLSFull)
	assert.NoError(t, err)
	assert.Equal(t, uint8(2), h.Version)
	assert.Equal(t, proxyproto.PROXY, h.Command)
	assert.Equal(t, proxyproto.TCPv4, h.TransportProtocol)

	// Verify TLVs are present
	tlvs, err := h.TLVs()
	assert.Nil(t, err)
	assert.True(t, len(tlvs) > 0, "should have TLVs when TLS state is provided")

	typeSet := make(map[proxyproto.PP2Type]bool)
	for _, tlv := range tlvs {
		typeSet[tlv.Type] = true
	}
	assert.True(t, typeSet[proxyproto.PP2_TYPE_SSL])
	assert.True(t, typeSet[proxyproto.PP2_TYPE_AUTHORITY])
}

func TestProxyProtoHeaderWithoutTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	h, err := proxyProtoHeader(conn, nil, ProxyProtocolTLSFull)
	assert.NoError(t, err)
	assert.Equal(t, uint8(2), h.Version)

	// Verify no TLVs when no TLS state
	tlvs, err := h.TLVs()
	assert.Nil(t, err)
	assert.Empty(t, tlvs, "should have no TLVs when TLS state is nil")
}

func TestProxyProtocolTLSModeSuccess(t *testing.T) {
	cert, _ := selfSignedCert(t)

	// TLS listener (incoming)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	incoming := tls.NewListener(tcpLn, tlsCfg)

	// Plain TCP target (backend)
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)

	dialer := func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", target.Addr().String())
	}

	p := New(incoming, Timeouts{Connect: 5 * time.Second, Close: 5 * time.Second, MaxLifetime: 5 * time.Second}, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolTLS, nil)
	go p.Accept()
	defer p.Shutdown()

	// Connect with TLS client
	src, err := tls.Dial("tcp", incoming.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.com",
	})
	assert.Nil(t, err)

	dst, err := target.Accept()
	assert.Nil(t, err)

	// Read and verify PROXY protocol header on backend
	header, err := proxyproto.Read(bufio.NewReaderSize(dst, 512))
	assert.Nil(t, err, "should be able to read proxy protocol header")
	assert.Equal(t, uint8(2), header.Version)
	assert.Equal(t, proxyproto.PROXY, header.Command)
	assert.Equal(t, proxyproto.TCPv4, header.TransportProtocol)

	// Verify TLVs contain TLS metadata
	tlvs, err := header.TLVs()
	assert.Nil(t, err)

	typeSet := make(map[proxyproto.PP2Type]bool)
	for _, tlv := range tlvs {
		typeSet[tlv.Type] = true
	}
	assert.True(t, typeSet[proxyproto.PP2_TYPE_SSL], "should have SSL TLV")
	assert.True(t, typeSet[proxyproto.PP2_TYPE_AUTHORITY], "should have Authority (SNI) TLV")

	// Verify data flows through
	_, _ = src.Write([]byte("A"))
	received := make([]byte, 1)
	for {
		n, err := dst.Read(received)
		if !errors.Is(err, io.EOF) {
			assert.Nil(t, err, "should receive data on target")
		}
		if n == 1 {
			break
		}
	}
	assert.Equal(t, []byte("A"), received)

	p.Shutdown()
	dst.Close()
	src.Close()
	p.Wait()
}

func TestProxyProtoHeaderConnMode(t *testing.T) {
	_, parsedCert := selfSignedCert(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer ln.Close()

	go func() {
		c, _ := ln.Accept()
		if c != nil {
			c.Close()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		ServerName:       "example.com",
		PeerCertificates: []*x509.Certificate{parsedCert},
	}

	// Conn mode should send connection info but no TLVs, even with TLS state
	h, err := proxyProtoHeader(conn, state, ProxyProtocolConn)
	assert.NoError(t, err)
	assert.Equal(t, uint8(2), h.Version)
	assert.Equal(t, proxyproto.PROXY, h.Command)

	tlvs, err := h.TLVs()
	assert.Nil(t, err)
	assert.Empty(t, tlvs, "conn mode should have no TLVs even with TLS state")
}

func TestProxyProtoHeaderTLVOverflowFailsClosed(t *testing.T) {
	oversized := &x509.Certificate{Raw: make([]byte, 65600), Subject: pkix.Name{CommonName: "overflow"}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	defer ln.Close()
	go func() {
		if c, _ := ln.Accept(); c != nil {
			c.Close()
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err)
	defer conn.Close()

	state := &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "example.com",
		PeerCertificates: []*x509.Certificate{oversized}}

	// tls-full: TLV overflow must fail CLOSED (error, not a stripped header).
	h, err := proxyProtoHeader(conn, state, ProxyProtocolTLSFull)
	assert.Error(t, err, "oversized cert TLV must fail closed in tls-full mode")
	assert.Nil(t, h)

	// conn mode skips the TLV block entirely — must never error.
	h, err = proxyProtoHeader(conn, state, ProxyProtocolConn)
	assert.NoError(t, err)
	assert.NotNil(t, h)
}

// failWriteConn is a mock connection that tracks Close() calls and fails on Write().
// Used to simulate a PROXY protocol header write failure.
type failWriteConn struct {
	closed bool
	mockConn
}

func (f *failWriteConn) Write(b []byte) (int, error) { return 0, errors.New("write error") }
func (f *failWriteConn) Close() error                { f.closed = true; return nil }

func TestProxyProtocolWriteFailureClosesBackend(t *testing.T) {
	// Incoming listener (plain TCP — forceHandshake is a no-op for non-TLS)
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()

	// Backend mock that fails on Write (simulating PROXY header write failure)
	backend := &failWriteConn{}
	dialCalled := make(chan struct{})

	dialer := func(_ context.Context) (net.Conn, error) {
		close(dialCalled)
		return backend, nil
	}

	// Regression: a PROXY header write failure must be recorded as an error.
	// Prometheus counters are monotonic, so assert on before/after deltas.
	errBefore := errorCount()
	successBefore := successCount()

	// Create proxy with PROXY protocol enabled
	p := proxyForTestWithProxyProtocol(incoming, dialer)
	go p.Accept()

	// Connect a client to trigger the handler
	client, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err)

	// Wait for the handler to reach Dial, ensuring it's past the accept stage
	<-dialCalled
	client.Close()

	// Shut down and wait for all handlers to complete
	p.Shutdown()
	p.Wait()

	// Regression: verify backend connection is closed when PROXY header write fails.
	assert.True(t, backend.closed, "backend connection must be closed when PROXY protocol header write fails")

	assert.Equal(t, int64(1), errorCount()-errBefore, "PROXY header write failure must increment accept.error")
	assert.Equal(t, int64(0), successCount()-successBefore, "PROXY header write failure must not increment accept.success")
}

// tcpConnPair returns the two ends of a connected localhost TCP socket. Both
// ends are *net.TCPConn, so tests exercise the real CloseRead/CloseWrite
// half-close behavior the teardown relies on (net.Pipe would not).
func tcpConnPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.Nil(t, err, "should be able to listen on random port")
	defer ln.Close()

	type acceptResult struct {
		conn net.Conn
		err  error
	}
	acceptC := make(chan acceptResult, 1)
	go func() {
		c, err := ln.Accept()
		acceptC <- acceptResult{c, err}
	}()

	dial, err := net.Dial("tcp", ln.Addr().String())
	require.Nil(t, err, "should be able to dial the listener")

	res := <-acceptC
	require.Nil(t, res.err, "should accept the connection")
	return dial, res.conn
}

// rollingProxy builds a proxy wired for the half-close teardown tests: no real
// listener/dialer, the given close/max-lifetime timeouts, and the given logger.
func rollingProxy(closeTimeout, maxConnLifetime time.Duration, logger Logger, flags int) *Proxy {
	return idleProxy(closeTimeout, 0, maxConnLifetime, logger, flags)
}

// idleProxy builds a proxy wired for the connection-wide idle-timeout tests:
// no real listener/dialer, the given close/idle/max-lifetime timeouts, and the
// given logger.
func idleProxy(closeTimeout, idleTimeout, maxConnLifetime time.Duration, logger Logger, flags int) *Proxy {
	return New(nil, Timeouts{
		Connect:     5 * time.Second,
		Close:       closeTimeout,
		Idle:        idleTimeout,
		MaxLifetime: maxConnLifetime,
	}, 0, nil, logger, flags, ProxyProtocolOff, nil)
}

// TestTrackedConnWriteRecordsActivity guards the watchdog activity clock for
// slow-draining transfers: a completed write is data movement and must reset
// the idle clock, so a transfer whose reads went quiet while a write drains is
// not reaped as stale.
func TestTrackedConnWriteRecordsActivity(t *testing.T) {
	p := idleProxy(time.Minute, time.Minute, 0, &testLogger{}, LogEverything)
	w := p.newPairWatchdog(&mockConn{}, &mockConn{})

	before := w.lastActivityTime()
	time.Sleep(5 * time.Millisecond)

	tc := &trackedConn{conn: &mockConn{}, watchdog: w}
	_, err := tc.Write([]byte("data"))
	require.Nil(t, err, "mock write should succeed")
	assert.True(t, w.lastActivityTime().After(before),
		"a successful write must reset the watchdog idle clock")
}

// TestFuseReturnsPromptlyAfterCleanClose guards the inline-watchdog structure.
// The second directionFinished() must close doneC so that runWatchdog, which
// runs on the fuse goroutine, returns as soon as both directions are done. A
// regression here would leave every cleanly-closed connection holding fuse and
// the accept handler's semaphore slot for a full CloseTimeout after the peers
// hang up. That is 60s at the default settings.
func TestFuseReturnsPromptlyAfterCleanClose(t *testing.T) {
	// Large CloseTimeout: if fuse's return depended on a close-timeout reap,
	// the bound below would trip long before the 60s window expired.
	p := idleProxy(60*time.Second, 0, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)

	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Move a little data end-to-end, then close both peers cleanly.
	_, err := clientConn.Write([]byte("ping"))
	require.Nil(t, err, "client write should succeed")
	buf := make([]byte, 4)
	_, err = io.ReadFull(backendConn, buf)
	require.Nil(t, err, "backend should receive the client's bytes")
	require.Nil(t, clientConn.Close(), "client close should succeed")
	require.Nil(t, backendConn.Close(), "backend close should succeed")

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fuse did not return promptly after a clean close; the watchdog is waiting out CloseTimeout")
	}
}

// TestRollingDeadlineKeepsActiveTransferAlive is the headline behavior: once a
// client half-closes, return traffic that keeps moving must NOT be cut off at
// CloseTimeout. The backend dribbles a chunk every 100ms (< the 200ms
// CloseTimeout) for ~800ms, and the client must receive every chunk. Under the
// old absolute-deadline code the surviving direction would be reaped ~200ms
// after the half-close and the client would see only the first chunk or two.
func TestRollingDeadlineKeepsActiveTransferAlive(t *testing.T) {
	p := rollingProxy(200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Client sends a request; backend receives it (both directions still open).
	_, err := clientConn.Write([]byte("request"))
	assert.Nil(t, err)
	_ = backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reqBuf := make([]byte, len("request"))
	_, err = io.ReadFull(backendConn, reqBuf)
	assert.Nil(t, err, "backend should receive the request")

	// Client half-closes its write side: this arms the teardown state.
	assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

	// Backend dribbles chunks every 100ms, total ~800ms == 4x CloseTimeout.
	const chunks = 8
	go func() {
		for i := range chunks {
			time.Sleep(100 * time.Millisecond)
			if _, err := backendConn.Write([]byte{byte('A' + i)}); err != nil {
				return
			}
		}
	}()

	// The client must receive every chunk despite the 200ms CloseTimeout.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, chunks)
	n, err := io.ReadFull(clientConn, got)
	assert.Nil(t, err, "rolling deadline must keep the active half-closed transfer alive")
	assert.Equal(t, chunks, n, "client must receive all return-traffic chunks")

	// Backend goes away; the idle reaper closes the pair and fuse returns.
	backendConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fuse did not return after the backend closed")
	}
}

// TestRollingDeadlineIdleReap verifies the reaper still fires: after a
// half-close with no return traffic, the surviving direction is closed after
// ~CloseTimeout of silence rather than lingering forever.
func TestRollingDeadlineIdleReap(t *testing.T) {
	p := rollingProxy(200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Half-close the client write side; the backend stays completely silent.
	assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

	select {
	case <-done:
		// Reaped after ~CloseTimeout; bound generously (well under 5x) for slow CI.
		assert.Less(t, time.Since(start), time.Second,
			"idle half-closed connection must be reaped well within 5x CloseTimeout")
	case <-time.After(3 * time.Second):
		t.Fatal("idle half-closed connection was never reaped")
	}
}

// TestRollingDeadlineReapsCounted asserts that every watchdog reap increments
// conn.timeout — close-timeout reaps of half-closed pairs included — and that
// a reap is reported as a timeout, never as an "error during copy".
func TestRollingDeadlineReapsCounted(t *testing.T) {
	countCopyErrorLogs := func(logs []string) int {
		n := 0
		for _, f := range logs {
			if strings.HasPrefix(f, "error during copy:") {
				n++
			}
		}
		return n
	}

	t.Run("half-closed idle reap is counted, not an error", func(t *testing.T) {
		var logs []string
		lg := &callbackLogger{callback: func(format string, v ...any) {
			logs = append(logs, format)
		}}
		p := rollingProxy(200*time.Millisecond, 0, lg, LogEverything)

		clientConn, proxyClient := tcpConnPair(t)
		proxyBackend, backendConn := tcpConnPair(t)
		defer clientConn.Close()
		defer backendConn.Close()

		before := connTimeoutCount()
		done := make(chan struct{})
		go func() {
			p.fuse(proxyClient, proxyBackend)
			close(done)
		}()

		assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("idle half-closed connection was never reaped")
		}

		assert.Equal(t, int64(1), connTimeoutCount()-before,
			"half-closed idle reap must increment conn.timeout")
		assert.Equal(t, 0, countCopyErrorLogs(logs),
			"half-closed idle reap must not log an error during copy")
	})

	t.Run("max-conn-lifetime timeout is still counted", func(t *testing.T) {
		// Large CloseTimeout so only the 200ms MaxConnLifetime can fire; no
		// half-close, so the timeout is observed while not half-closed.
		p := rollingProxy(5*time.Second, 200*time.Millisecond, &testLogger{}, LogConnectionErrors)

		clientConn, proxyClient := tcpConnPair(t)
		proxyBackend, backendConn := tcpConnPair(t)
		defer clientConn.Close()
		defer backendConn.Close()

		before := connTimeoutCount()
		done := make(chan struct{})
		go func() {
			p.fuse(proxyClient, proxyBackend)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("max-conn-lifetime did not reap the idle connection")
		}

		assert.Equal(t, int64(1), connTimeoutCount()-before,
			"max-conn-lifetime timeout must increment conn.timeout exactly once (single watchdog reap site)")
	})

	t.Run("max-conn-lifetime timeout on half-closed pair is counted", func(t *testing.T) {
		// Large CloseTimeout so only the 200ms MaxConnLifetime can fire; the
		// client half-closes immediately, so the lifetime cap reaps a
		// half-closed pair. The reap is a policy event, not silent teardown.
		p := rollingProxy(5*time.Second, 200*time.Millisecond, &testLogger{}, LogConnectionErrors)

		clientConn, proxyClient := tcpConnPair(t)
		proxyBackend, backendConn := tcpConnPair(t)
		defer clientConn.Close()
		defer backendConn.Close()

		before := connTimeoutCount()
		done := make(chan struct{})
		go func() {
			p.fuse(proxyClient, proxyBackend)
			close(done)
		}()

		assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("max-conn-lifetime did not reap the half-closed connection")
		}

		assert.Equal(t, int64(1), connTimeoutCount()-before,
			"max-conn-lifetime timeout on a half-closed pair must increment conn.timeout")
	})
}

// TestRollingDeadlineClampedByMaxConnLifetime verifies that rolling extensions
// never push a deadline past MaxConnLifetime. With CloseTimeout=200ms and
// MaxConnLifetime=500ms, a backend that dribbles forever would keep the
// connection alive indefinitely without the clamp; with it, the connection
// must die at ~500ms.
func TestRollingDeadlineClampedByMaxConnLifetime(t *testing.T) {
	p := rollingProxy(200*time.Millisecond, 500*time.Millisecond, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Half-close to arm, then dribble return traffic every 100ms indefinitely.
	assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := backendConn.Write([]byte{'x'}); err != nil {
				return
			}
		}
	}()
	go func() { _, _ = io.Copy(io.Discard, clientConn) }()

	select {
	case <-done:
		elapsed := time.Since(start)
		close(stop)
		assert.Greater(t, elapsed, 400*time.Millisecond,
			"connection must survive until close to max-conn-lifetime")
		assert.Less(t, elapsed, time.Second,
			"rolling extension must be clamped by max-conn-lifetime, not run forever")
	case <-time.After(3 * time.Second):
		close(stop)
		t.Fatal("rolling extension was not clamped by max-conn-lifetime")
	}
}

// TestZeroCloseTimeoutPromptClosure guards the documented flag behavior: with
// --close-timeout=0, the surviving direction is closed immediately once the
// peer half-closes.
func TestZeroCloseTimeoutPromptClosure(t *testing.T) {
	p := rollingProxy(0, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

	select {
	case <-done:
		assert.Less(t, time.Since(start), 500*time.Millisecond,
			"zero close-timeout must close the surviving direction promptly")
	case <-time.After(2 * time.Second):
		t.Fatal("zero close-timeout did not promptly close the connection")
	}
}

// TestAbortiveCloseReapsPeerAfterCloseTimeout verifies that when one end aborts
// the connection (RST), the surviving direction is NOT collapsed to an immediate
// reap but is given CloseTimeout to drain, exactly like a graceful half-close.
// An RST on one physical connection says nothing about whether the other
// physical connection still has deliverable data (e.g. a unix-socket backend
// that wrote its response and then reset); the half-close transition gives the
// survivor CloseTimeout of silence before the watchdog reaps it.
func TestAbortiveCloseReapsPeerAfterCloseTimeout(t *testing.T) {
	// Small CloseTimeout so the survivor is reaped promptly but only after the
	// rolling idle window, never instantly.
	p := rollingProxy(200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Abort the client side with a RST (SO_LINGER 0 + Close). The backend stays
	// idle and open, so the surviving backend->client direction is reaped after
	// CloseTimeout of silence -- not immediately, and not only at some large cap.
	assert.Nil(t, clientConn.(*net.TCPConn).SetLinger(0))
	assert.Nil(t, clientConn.Close())

	select {
	case <-done:
		elapsed := time.Since(start)
		assert.Greater(t, elapsed, 100*time.Millisecond,
			"an abortive close (RST) must not collapse the survivor's deadline to an immediate reap")
		assert.Less(t, elapsed, 2*time.Second,
			"the surviving direction must be reaped after CloseTimeout of silence")
	case <-time.After(3 * time.Second):
		t.Fatal("abortive close did not reap the surviving direction")
	}
}

// TestIdleTimeoutReapsIdleConnection verifies the basic idle timeout: with both
// directions open and neither peer sending, the pair is reaped after
// ~IdleTimeout of silence (no half-close involved).
func TestIdleTimeoutReapsIdleConnection(t *testing.T) {
	p := idleProxy(60*time.Second, 200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Neither side sends anything. The connection must be reaped after
	// ~IdleTimeout; bound generously (well under 5x) for slow CI.
	select {
	case <-done:
		assert.Less(t, time.Since(start), time.Second,
			"fully idle connection must be reaped well within 5x IdleTimeout")
	case <-time.After(3 * time.Second):
		t.Fatal("fully idle connection was never reaped")
	}

	// The proxy-side conns are closed, so the client observes EOF.
	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := clientConn.Read(make([]byte, 1))
	assert.Equal(t, io.EOF, err, "client must see EOF after the idle reap closes the pair")
}

// TestIdleTimeoutDoesNotReapAsymmetricTransfer is THE regression test: idle is a
// property of the connection, not a direction. The client sends one request then
// goes silent (does NOT half-close) while the backend streams a chunk every
// ~100ms (< IdleTimeout) for ~1s (5x IdleTimeout). The client must receive every
// chunk: activity on the backend->client direction keeps the silent
// client->backend direction alive. A per-direction idle deadline (no bump-both)
// would reap the silent direction mid-stream and fail this test.
func TestIdleTimeoutDoesNotReapAsymmetricTransfer(t *testing.T) {
	p := idleProxy(60*time.Second, 200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Client sends a request; backend receives it. Both directions still open.
	_, err := clientConn.Write([]byte("request"))
	assert.Nil(t, err)
	_ = backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reqBuf := make([]byte, len("request"))
	_, err = io.ReadFull(backendConn, reqBuf)
	assert.Nil(t, err, "backend should receive the request")

	// Client now goes silent (no half-close). Backend dribbles chunks every
	// 100ms, total ~1s == 5x IdleTimeout.
	const chunks = 10
	go func() {
		for i := range chunks {
			time.Sleep(100 * time.Millisecond)
			if _, err := backendConn.Write([]byte{byte('A' + i)}); err != nil {
				return
			}
		}
	}()

	// The client must receive every chunk despite the 200ms IdleTimeout and its
	// own silence -- the connection-wide idle clock is reset by backend activity.
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, chunks)
	n, err := io.ReadFull(clientConn, got)
	assert.Nil(t, err, "connection-wide idle timeout must keep the asymmetric transfer alive")
	assert.Equal(t, chunks, n, "client must receive all streamed chunks")

	// Both peers go away (EOF in both directions); fuse returns promptly without
	// waiting on the large CloseTimeout used to isolate the idle behavior above.
	backendConn.Close()
	clientConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fuse did not return after both peers closed")
	}
}

// TestIdleTimeoutActivityResetsClock verifies that steady activity keeps a
// connection up across many IdleTimeout windows, and that it is reaped once the
// activity stops.
func TestIdleTimeoutActivityResetsClock(t *testing.T) {
	p := idleProxy(60*time.Second, 200*time.Millisecond, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	// Drain whatever the client dribbles through to the backend.
	go func() { _, _ = io.Copy(io.Discard, backendConn) }()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Dribble one byte every ~100ms (half the IdleTimeout) for ~1s: 5 windows.
	const beats = 10
	for range beats {
		time.Sleep(100 * time.Millisecond)
		if _, err := clientConn.Write([]byte{'x'}); err != nil {
			t.Fatalf("write during dribble failed: %s", err)
		}
	}

	// The connection must still be alive after several windows of activity.
	select {
	case <-done:
		t.Fatal("active connection was reaped despite steady activity")
	default:
	}
	assert.Greater(t, time.Since(start), time.Second,
		"connection survived the full dribble period")

	// Now go silent: the connection must be reaped after ~IdleTimeout.
	silentStart := time.Now()
	select {
	case <-done:
		assert.Less(t, time.Since(silentStart), time.Second,
			"connection must be reaped within 5x IdleTimeout once activity stops")
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection was never reaped after activity stopped")
	}
}

// TestIdleTimeoutZeroNeverReaps guards the default (--idle-timeout=0): an idle
// connection with no half-close and no lifetime cap must live indefinitely,
// exactly as before this feature existed.
func TestIdleTimeoutZeroNeverReaps(t *testing.T) {
	p := idleProxy(60*time.Second, 0, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Both sides idle for well over any small idle duration: must stay open.
	select {
	case <-done:
		t.Fatal("idle-timeout=0 must never reap an idle connection")
	case <-time.After(600 * time.Millisecond):
	}

	// Tear it down manually and confirm fuse returns (no goroutine leak).
	clientConn.Close()
	backendConn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("fuse did not return after manual close")
	}
}

// TestIdleTimeoutReapLoggedNotErrored asserts that an idle-timeout reap is
// treated as a deliberate policy close: it increments conn.timeout exactly once
// and logs at the connection level, NOT as "error during copy".
func TestIdleTimeoutReapLoggedNotErrored(t *testing.T) {
	var mu sync.Mutex
	var logs []string
	lg := &callbackLogger{callback: func(format string, v ...any) {
		mu.Lock()
		logs = append(logs, format)
		mu.Unlock()
	}}
	p := idleProxy(60*time.Second, 200*time.Millisecond, 0, lg, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	before := connTimeoutCount()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle connection was never reaped")
	}

	mu.Lock()
	defer mu.Unlock()
	timeoutCount, sawError := 0, false
	for _, f := range logs {
		if strings.HasPrefix(f, "connection closed by timeout:") {
			timeoutCount++
		}
		if strings.HasPrefix(f, "error during copy:") {
			sawError = true
		}
	}
	assert.Equal(t, 1, timeoutCount, "idle reap must log exactly one 'connection closed by timeout' message")
	assert.False(t, sawError, "idle reap must not log an 'error during copy' message")
	assert.Equal(t, int64(1), connTimeoutCount()-before,
		"idle reap must increment conn.timeout exactly once")
}

// TestIdleTimeoutHalfCloseTransition verifies that once a connection half-closes
// the surviving direction is governed by CloseTimeout, not IdleTimeout. With
// IdleTimeout=1s and CloseTimeout=200ms, the survivor of a half-close that then
// goes idle must be reaped in ~200ms, well under the 1s idle window.
func TestIdleTimeoutHalfCloseTransition(t *testing.T) {
	p := idleProxy(200*time.Millisecond, time.Second, 0, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Exchange a little data so both directions are live, then half-close the
	// client write side and let the backend go silent.
	_, err := clientConn.Write([]byte("hi"))
	assert.Nil(t, err)
	_ = backendConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = io.ReadFull(backendConn, make([]byte, 2))
	assert.Nil(t, err, "backend should receive the request")

	halfCloseStart := time.Now()
	assert.Nil(t, clientConn.(*net.TCPConn).CloseWrite())

	select {
	case <-done:
		// Governed by the 200ms CloseTimeout, not the 1s IdleTimeout.
		assert.Less(t, time.Since(halfCloseStart), 700*time.Millisecond,
			"after half-close the survivor must be governed by CloseTimeout, not IdleTimeout")
	case <-time.After(3 * time.Second):
		t.Fatal("half-closed survivor was never reaped")
	}
}

// TestIdleTimeoutClampedByMaxConnLifetime verifies that MaxConnLifetime caps the
// idle extension: with IdleTimeout=200ms and MaxConnLifetime=500ms, a client
// that dribbles forever (resetting the idle clock every 100ms) is still reaped
// at ~500ms rather than living indefinitely.
func TestIdleTimeoutClampedByMaxConnLifetime(t *testing.T) {
	p := idleProxy(60*time.Second, 200*time.Millisecond, 500*time.Millisecond, &testLogger{}, LogEverything)

	clientConn, proxyClient := tcpConnPair(t)
	proxyBackend, backendConn := tcpConnPair(t)
	defer clientConn.Close()
	defer backendConn.Close()

	// Drain the forwarded dribble at the backend.
	go func() { _, _ = io.Copy(io.Discard, backendConn) }()

	start := time.Now()
	done := make(chan struct{})
	go func() {
		p.fuse(proxyClient, proxyBackend)
		close(done)
	}()

	// Dribble every 100ms (< IdleTimeout) indefinitely; the idle clock keeps
	// resetting, so only the lifetime clamp can reap the connection.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := clientConn.Write([]byte{'x'}); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		close(stop)
		assert.Greater(t, elapsed, 400*time.Millisecond,
			"connection must survive until close to max-conn-lifetime")
		assert.Less(t, elapsed, time.Second,
			"idle extension must be clamped by max-conn-lifetime, not run forever")
	case <-time.After(3 * time.Second):
		close(stop)
		t.Fatal("idle extension was not clamped by max-conn-lifetime")
	}
}
