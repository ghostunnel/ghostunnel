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

func (t *testLogger) Printf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
}

func TestMultipleShutdownCalls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	p := New(ln, 10*time.Second, 10*time.Second, nil, &testLogger{}, LogEverything, false)

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

	// Target listener
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	dialer := func() (net.Conn, error) {
		return net.Dial("tcp", target.Addr().String())
	}

	// Start accept loop
	p := New(incoming, 10*time.Second, 10*time.Second, dialer, &testLogger{}, LogEverything, false)
	go p.Accept()
	defer p.Shutdown()

	// Proxy a connection
	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")

	dst, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")

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

func TestProxyProtocolSuccess(t *testing.T) {
	// Incoming listener
	incoming, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	// Target listener
	target, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	dialer := func() (net.Conn, error) {
		return net.Dial("tcp", target.Addr().String())
	}

	// Start accept loop
	p := New(incoming, 10*time.Second, 10*time.Second, dialer, &testLogger{}, LogEverything, true)
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

	dialer := func() (net.Conn, error) {
		return nil, errors.New("failure for test")
	}

	p := New(ln, 10*time.Second, 10*time.Second, dialer, &testLogger{}, LogEverything, false)
	go p.Accept()
	defer p.Shutdown()

	// Open a connection, should get reset once backend dial fails
	src, err := net.Dial("tcp", ln.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")
	defer src.Close()

	failed := false
	for i := 0; i < 100; i++ {
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
	proxy := New(nil, 10*time.Second, 10*time.Second, nil, &testLogger{}, LogEverything, false)

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
	for i := 0; i < size; i++ {
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
