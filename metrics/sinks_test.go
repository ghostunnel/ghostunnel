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

package metrics

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// discardLogger satisfies Logger while dropping output, for push-loop tests.
var discardLogger = log.New(io.Discard, "", 0)

// TestServeHTTPJSON verifies the /_metrics JSON handler emits a JSON array with
// the expected content type.
func TestServeHTTPJSON(t *testing.T) {
	r, _ := fixture(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_metrics/json", nil)
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var entries []map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	assert.NotEmpty(t, entries)
}

// TestPostLoop verifies --metrics-url POSTs a JSON body matching the snapshot.
func TestPostLoop(t *testing.T) {
	r, _ := fixture(t)

	bodies := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
		b, _ := io.ReadAll(req.Body)
		select {
		case bodies <- b:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r.StartPostLoop(srv.URL, srv.Client(), 10*time.Millisecond, discardLogger)

	select {
	case b := <-bodies:
		var entries []map[string]any
		require.NoError(t, json.Unmarshal(b, &entries))
		found := false
		for _, e := range entries {
			if e["metric"] == "ghostunnel.accept.total" {
				found = true
			}
		}
		assert.True(t, found, "POST body must contain ghostunnel.accept.total")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for metrics POST")
	}
}

// TestGraphiteFlushDialError verifies graphiteFlush surfaces a dial failure
// rather than panicking or silently succeeding.
func TestGraphiteFlushDialError(t *testing.T) {
	r, _ := fixture(t)
	// Port 1 on loopback refuses connections, so the dial fails.
	err := r.graphiteFlush(&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1})
	assert.Error(t, err)
}

// failingWriter fails every write, standing in for a TCP connection whose peer
// has gone away mid-report.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("connection reset")
}

// TestGraphiteWriteError verifies a write failure mid-report is surfaced
// rather than swallowed: a partial push must not be reported as success.
func TestGraphiteWriteError(t *testing.T) {
	r, _ := fixture(t)
	err := r.writeGraphite(failingWriter{}, 1700000000)
	assert.Error(t, err, "a failed write must surface an error")
}

// TestPostOnceNon2xx verifies a reachable receiver that rejects the payload is
// treated as a failed report, not a success.
func TestPostOnceNon2xx(t *testing.T) {
	r, _ := fixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := r.postOnce(srv.URL, srv.Client())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500", "the receiver's status should be surfaced")
}

// TestPostOnceSuccess pins the happy path of the status-code check: any 2xx
// (not just 200) is a successful report.
func TestPostOnceSuccess(t *testing.T) {
	r, _ := fixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	assert.NoError(t, r.postOnce(srv.URL, srv.Client()))
}

// TestGraphitePush verifies --metrics-graphite writes the line protocol over TCP.
func TestGraphitePush(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	lines := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var sb strings.Builder
		sc := bufio.NewScanner(conn)
		for sc.Scan() {
			sb.WriteString(sc.Text())
			sb.WriteString("\n")
		}
		if err := sc.Err(); err != nil {
			return
		}
		select {
		case lines <- sb.String():
		default:
		}
	}()

	r, _ := fixture(t)
	r.StartGraphitePush(ln.Addr().(*net.TCPAddr), 10*time.Millisecond, discardLogger)

	select {
	case out := <-lines:
		assert.Contains(t, out, "ghostunnel.accept.total.count 3 ")
		assert.Contains(t, out, "ghostunnel.conn.handshake.count 3 ")
		assert.Contains(t, out, "ghostunnel.conn.handshake.99-percentile ")
		assert.NotContains(t, out, "ghostunnel.conn.handshake.min ")
		assert.NotContains(t, out, "ghostunnel.conn.handshake.max ")
		assert.NotContains(t, out, "std-dev")
		assert.NotContains(t, out, "count_ps")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for graphite flush")
	}
}

// TestGraphiteWriteConnHonorsDeadline verifies writeGraphiteConn bounds the
// write with a deadline: a peer that accepts the connection but never reads
// must yield a timeout error rather than blocking forever. net.Pipe is
// synchronous, so the buffered flush blocks until the deadline fires.
func TestGraphiteWriteConnHonorsDeadline(t *testing.T) {
	r, _ := fixture(t)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	// server is never read from, so the write on client blocks until the
	// deadline.

	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- r.writeGraphiteConn(client, 20*time.Millisecond, 1700000000) }()

	select {
	case err := <-done:
		require.Error(t, err, "an unread peer must surface a deadline error")
		assert.Less(t, time.Since(start), 2*time.Second, "writeGraphiteConn must return promptly, not hang")
	case <-time.After(5 * time.Second):
		t.Fatal("writeGraphiteConn did not honor the deadline")
	}
}
