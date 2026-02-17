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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
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
	return New(listener, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, false)
}

func proxyForTestWithProxyProtocol(listener net.Listener, dialer DialFunc) *Proxy {
	return New(listener, 5*time.Second, 5*time.Second, 5*time.Second, 1, dialer, &testLogger{}, LogEverything, true)
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

func TestLogConnectionMessageDisabled(t *testing.T) {
	// Test with LogConnections disabled
	p := New(nil, 5*time.Second, 5*time.Second, 0, 0, nil, &testLogger{}, 0, false)

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
	p := New(nil, 5*time.Second, 5*time.Second, 0, 0, nil, logger, LogConnectionErrors, false)
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
