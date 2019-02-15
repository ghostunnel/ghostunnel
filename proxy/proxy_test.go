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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type testLogger struct{}

func (t *testLogger) Printf(format string, v ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", v...)
}

func TestMultipleShutdownCalls(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err, "should be able to listen on random port")

	p := New(ln, 60*time.Second, nil, &testLogger{}, false)

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
	p := New(incoming, 60*time.Second, dialer, &testLogger{}, false)
	go p.Accept()
	defer p.Shutdown()

	// Proxy a connection
	src, err := net.Dial("tcp", incoming.Addr().String())
	assert.Nil(t, err, "should be able to dial into proxy")

	dst, err := target.Accept()
	assert.Nil(t, err, "should be able to receive connection on target")

	src.Write([]byte("A"))

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

	p := New(ln, 60*time.Second, dialer, &testLogger{}, false)
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
