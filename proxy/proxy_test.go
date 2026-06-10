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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
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
	return New(listener, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolOff)
}

func proxyForTestWithProxyProtocol(listener net.Listener, dialer DialFunc) *Proxy {
	return New(listener, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolConn)
}

func TestAbortedConnection(t *testing.T) {
	p := proxyForTest(&failingListener{}, nil)

	// Run proxy -- accept will always fail
	go p.Accept()
	defer p.Shutdown()

	errorCounter.Clear()
	for range 10 {
		if errorCounter.Count() != 0 {
			return
		}
		time.Sleep(1 * time.Second)
	}

	t.Error("expected proxy to report errors, but got none")
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
		if err != io.EOF {
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
	assert.Equal(t, header.Command, proxyproto.ProtocolVersionAndCommand(proxyproto.PROXY))
	assert.Equal(t, header.TransportProtocol, proxyproto.AddressFamilyAndProtocol(proxyproto.TCPv4))
	assert.Equal(t, header.SourceAddr.(*net.TCPAddr).IP, net.ParseIP("127.0.0.1").To4())
	assert.Equal(t, header.DestinationAddr.(*net.TCPAddr).IP, net.ParseIP("127.0.0.1").To4())
	assert.Equal(t, header.SourceAddr.(*net.TCPAddr).Port, src.LocalAddr().(*net.TCPAddr).Port)
	assert.Equal(t, header.DestinationAddr.(*net.TCPAddr).Port, incoming.Addr().(*net.TCPAddr).Port)

	_, _ = src.Write([]byte("A"))

	received := make([]byte, 1)
	for {
		n, err := dst.Read(received)
		if err != io.EOF {
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

	target, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		_ = incoming.Close()
		t.Skip("IPv6 not available for backend")
	}

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
	assert.Equal(t, proxyproto.ProtocolVersionAndCommand(proxyproto.PROXY), header.Command)
	// Core assertion: transport protocol byte reports TCPv6.
	assert.Equal(t, proxyproto.AddressFamilyAndProtocol(proxyproto.TCPv6), header.TransportProtocol,
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
		proxy.copyData(dstIn, srcOut)
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
	if err != nil && err != io.EOF && !isClosedConnectionError(err) {
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
			name: "net.OpError read closed",
			err: &net.OpError{
				Op:  "read",
				Err: errors.New("use of closed network connection"),
			},
			expected: true,
		},
		{
			name: "net.OpError write closed",
			err: &net.OpError{
				Op:  "write",
				Err: errors.New("use of closed network connection"),
			},
			expected: true,
		},
		{
			name: "net.OpError readfrom closed",
			err: &net.OpError{
				Op:  "readfrom",
				Err: errors.New("use of closed network connection"),
			},
			expected: true,
		},
		{
			name: "net.OpError writeto closed",
			err: &net.OpError{
				Op:  "writeto",
				Err: errors.New("use of closed network connection"),
			},
			expected: true,
		},
		{
			name: "net.OpError other op",
			err: &net.OpError{
				Op:  "dial",
				Err: errors.New("use of closed network connection"),
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isClosedConnectionError(tc.err)
			assert.Equal(t, tc.expected, result)
		})
	}
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

// fakeTimeoutErr is a net.Error with Timeout()==true; not a closed-conn error.
type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "i/o timeout (simulated)" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return false }

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
		p := New(nil, 5*time.Second, 5*time.Second, 0, 0, nil, lg, flags, ProxyProtocolOff)
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

	t.Run("real I/O error logged when LogConnectionErrors set", func(t *testing.T) {
		src := &readErrConn{
			payload: []byte("hello"),
			err:     errors.New("synthetic disk gone bad"),
		}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnectionErrors)
		before := connTimeoutCounter.Count()
		written := p.copyData(dst, src)
		after := connTimeoutCounter.Count()

		assert.Equal(t, int64(5), written, "payload should be copied before the error")
		assert.Equal(t, 1, countCopyErrorLogs(*logs), "real I/O error must be logged once")
		assert.Equal(t, before, after, "non-timeout error must not bump connTimeoutCounter")
	})

	t.Run("real I/O error suppressed when LogConnectionErrors cleared", func(t *testing.T) {
		src := &readErrConn{err: errors.New("synthetic disk gone bad")}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnections)
		_ = p.copyData(dst, src)

		assert.Equal(t, 0, countCopyErrorLogs(*logs),
			"copy errors must be silent without LogConnectionErrors")
	})

	t.Run("timeout error increments timeout counter and logs", func(t *testing.T) {
		src := &readErrConn{err: fakeTimeoutErr{}}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnectionErrors)
		before := connTimeoutCounter.Count()
		_ = p.copyData(dst, src)
		after := connTimeoutCounter.Count()

		assert.Equal(t, int64(1), after-before, "timeout must bump connTimeoutCounter")
		assert.Equal(t, 1, countCopyErrorLogs(*logs), "timeout must still be logged")
	})

	t.Run("closed-connection error is silently suppressed", func(t *testing.T) {
		src := &readErrConn{err: errors.New("io: read/write on closed pipe")}
		dst := newDiscardConn()
		defer dst.Close()

		p, logs := newCapturingProxy(LogConnectionErrors)
		before := connTimeoutCounter.Count()
		_ = p.copyData(dst, src)
		after := connTimeoutCounter.Count()

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
	err = forceHandshake(ctx, conn)
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
	p := New(nil, 5*time.Second, 5*time.Second, 0, 0, nil, &testLogger{}, 0, ProxyProtocolOff)

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
	p := New(nil, 5*time.Second, 5*time.Second, 0, 0, nil, logger, LogConnectionErrors, ProxyProtocolOff)
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

	t.Run("non-TCP fallback", func(t *testing.T) {
		conn := &mockConn{} // RemoteAddr returns *net.IPAddr, not *net.TCPAddr
		assert.Equal(t, proxyproto.TCPv4, transportProtocol(conn))
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

	h := proxyProtoHeader(conn, state, ProxyProtocolTLSFull, &testLogger{})
	assert.Equal(t, uint8(2), h.Version)
	assert.Equal(t, proxyproto.PROXY, proxyproto.ProtocolVersionAndCommand(h.Command))
	assert.Equal(t, proxyproto.TCPv4, proxyproto.AddressFamilyAndProtocol(h.TransportProtocol))

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

	h := proxyProtoHeader(conn, nil, ProxyProtocolTLSFull, &testLogger{})
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

	p := New(incoming, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, ProxyProtocolTLS)
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
	assert.Equal(t, proxyproto.PROXY, proxyproto.ProtocolVersionAndCommand(header.Command))
	assert.Equal(t, proxyproto.TCPv4, proxyproto.AddressFamilyAndProtocol(header.TransportProtocol))

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
		if err != io.EOF {
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
	h := proxyProtoHeader(conn, state, ProxyProtocolConn, &testLogger{})
	assert.Equal(t, uint8(2), h.Version)
	assert.Equal(t, proxyproto.PROXY, proxyproto.ProtocolVersionAndCommand(h.Command))

	tlvs, err := h.TLVs()
	assert.Nil(t, err)
	assert.Empty(t, tlvs, "conn mode should have no TLVs even with TLS state")
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
}
