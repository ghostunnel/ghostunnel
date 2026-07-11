/*-
 * Copyright 2015 Square Inc.
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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Mock net.Conn for testing
type fakeConn struct {
	io.ReadWriteCloser
}

func (c fakeConn) LocalAddr() net.Addr {
	return nil
}

func (c fakeConn) RemoteAddr() net.Addr {
	return nil
}

func (c fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (c fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func dummyDial(ctx context.Context) (net.Conn, error) {
	f, err := os.Open(os.DevNull)
	panicOnError(err)
	return fakeConn{f}, nil
}

func dummyDialError(ctx context.Context) (net.Conn, error) {
	return nil, errors.New("fail")
}

func TestStatusHandleWatchdogError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip()
		return
	}

	// Trigger watchdog functionality
	os.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	os.Setenv("WATCHDOG_USEC", "X")
	defer os.Unsetenv("WATCHDOG_PID")
	defer os.Unsetenv("WATCHDOG_USEC")

	err := handleServiceWatchdog(func() bool { return true }, nil)
	if err == nil {
		t.Error("handleServiceWatchdog did not handle invalid watchdog settings correctly")
	}
}

func TestStatusHandleWatchdog(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip()
		return
	}

	// Trigger watchdog functionality
	os.Setenv("WATCHDOG_PID", strconv.Itoa(os.Getpid()))
	os.Setenv("WATCHDOG_USEC", "1000000")
	defer os.Unsetenv("WATCHDOG_PID")
	defer os.Unsetenv("WATCHDOG_USEC")

	// Run watchdog, kill it after one iteration
	shutdown := make(chan bool, 1)
	done := make(chan bool, 1)
	go func() {
		err := handleServiceWatchdog(func() bool {
			// Send shutdown signal to stop handler
			shutdown <- true
			return true
		}, shutdown)
		if err != nil {
			t.Error(err)
		}
		done <- true
	}()

	timeout := time.NewTicker(30 * time.Second)
	defer timeout.Stop()

	select {
	case <-done:
		return
	case <-timeout.C:
		shutdown <- true
		t.Error("watchdog handler timed out, did not call health check")
		return
	}
}

func TestStatusHandlerNew(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, &http.Request{})

	if response.Code != 503 {
		t.Error("status should return 503 if not yet listening")
	}

	if response.Header().Get("Content-Type") != "application/json" {
		t.Error("status response should be application/json")
	}
}

func TestStatusHandlerListeningTCP(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, &http.Request{})

	if response.Code != 200 {
		t.Error("status should return 200 once listening")
	}

	if response.Header().Get("Content-Type") != "application/json" {
		t.Error("status response should be application/json")
	}
}

func TestStatusHandlerListeningBackendDown(t *testing.T) {
	handler := newStatusHandler(dummyDialError, "", "", "", "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, &http.Request{})

	if response.Code != 503 {
		t.Error("status should return 503 if backend is down")
	}
}

func TestStatusHandlerReloading(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.Reloading()
	handler.ServeHTTP(response, &http.Request{})

	if response.Code != 200 {
		t.Error("status should return 200 during reload")
	}
}

func TestStatusHandlerStopping(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.Stopping()
	handler.ServeHTTP(response, &http.Request{})

	if response.Code != 503 {
		t.Error("status should return 503 when stopping")
	}
}

func TestStatusHandlerResponses(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	resp := handler.status(context.Background())
	if resp.Message != "initializing" {
		t.Error("status should say 'initializing' on startup")
	}

	handler.Listening()
	resp = handler.status(context.Background())
	if resp.Message != "listening" {
		t.Error("status should say 'listening' after startup")
	}

	handler.Reloading()
	resp = handler.status(context.Background())
	if resp.Message != "reloading" {
		t.Error("status should say 'reloading' when reload initiated")
	}

	handler.Stopping()
	resp = handler.status(context.Background())
	if resp.Message != "stopping" {
		t.Error("status should say 'stopping' when shutdown initiated")
	}
}

func TestStatusTargetHTTP2XX(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(200)

	if !statusResp.Ok || statusResp.BackendStatus != "ok" || statusRespCode != 200 {
		t.Error("status should return 200 when status backend returns 200, but got:", statusResp, statusRespCode)
	}
}

func TestStatusTargetHTTPNon2XX(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(503)

	if statusResp.Ok || statusResp.BackendStatus == "ok" || statusRespCode != 503 {
		t.Error("status should return 503 when status backend returns something other than 200, but got:", statusResp, statusRespCode)
	}
}

func TestStatusTargetHTTPWithError(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(-1)

	if statusResp.Ok || statusResp.BackendStatus == "ok" || statusRespCode != 503 {
		t.Error("status should return 503 when status backend returns something other than 200, but got:", statusResp, statusRespCode)
	}
}

func TestServeHTTPReturnsJSON(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	handler.Listening()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != 200 {
		t.Errorf("expected status 200, got %d", response.Code)
	}

	var resp statusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}

	if resp.Message != "listening" {
		t.Errorf("expected message 'listening', got %q", resp.Message)
	}
	if !resp.Ok {
		t.Error("expected ok=true when listening with working backend")
	}
}

func TestServeHTTPBackendUnhealthy(t *testing.T) {
	handler := newStatusHandler(dummyDialError, "", "", "", "")
	handler.Listening()

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))

	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 503, got %d", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", got)
	}

	var resp statusResponse
	if err := json.Unmarshal(response.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response body: %v", err)
	}
	if resp.Ok {
		t.Error("expected resp.Ok=false when backend dial fails")
	}
	if resp.BackendOk {
		t.Error("expected resp.BackendOk=false when backend dial fails")
	}
	if resp.BackendStatus != "critical" {
		t.Errorf("expected BackendStatus=critical, got %q", resp.BackendStatus)
	}
	if resp.BackendError == "" {
		t.Error("expected non-empty BackendError describing dial failure")
	}
	if resp.Status != "critical" {
		t.Errorf("expected top-level Status=critical, got %q", resp.Status)
	}
}

func TestNonLinuxNotifyHelpersDoNotPanic(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux uses the real systemd implementation")
	}

	// These should not panic
	notifyServiceStatus("test")
	notifyServiceReady()
	notifyServiceReloading()
	notifyServiceStopping()

	err := handleServiceWatchdog(func() bool { return true }, nil)
	if err != nil {
		t.Errorf("handleServiceWatchdog stub should return nil, got: %v", err)
	}
}

func TestHandleWatchdogCallsSystemd(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	handler.Listening()
	// HandleWatchdog should not panic regardless of platform
	handler.HandleWatchdog()
}

// TestCheckBackendStatusInvalidURL covers the early-return error path in
// checkBackendStatus for when http.NewRequestWithContext fails to parse the
// configured statusTargetAddress. A control character in the URL is rejected
// by net/url before any dial is attempted.
func TestCheckBackendStatusInvalidURL(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "http://\x7f/")

	err := handler.checkBackendStatus(context.Background())
	if err == nil {
		t.Fatal("expected error from invalid statusTargetAddress")
	}
	if !strings.Contains(err.Error(), "invalid control character in URL") {
		t.Errorf("error = %q, want it to mention parse failure", err.Error())
	}
}

// statusTargetWithResponseStatusCode creates a stub status target that returns the status code specified by "code".
func statusTargetWithResponseStatusCode(code int) (statusResponse, int) {
	statusTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	defer statusTarget.Close()

	response := httptest.NewRecorder()
	handler := newStatusHandler(func(ctx context.Context) (net.Conn, error) {
		if code < 0 {
			return nil, errors.New("simulating error when talking to backend")
		}
		u, _ := url.Parse(statusTarget.URL) // NOTE: I tried using statusTarget.Config.Addr instead, but it wasn't set.
		return net.Dial("tcp", net.JoinHostPort(u.Hostname(), u.Port()))
	}, "", "", "", statusTarget.URL)

	req := httptest.NewRequest(http.MethodGet, "/not-empty", nil)
	handler.Listening() // NOTE: required for non-503 backend response code.
	handler.ServeHTTP(response, req)
	res := response.Result()
	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}

	statusResp := statusResponse{}
	_ = json.Unmarshal(data, &statusResp)

	return statusResp, res.StatusCode
}

// TestStoppingIsTerminal is a regression test: once Stopping() has been called
// (graceful shutdown begun), a timed reload firing mid-drain must not resurrect
// healthy state. Listening() after Stopping() must be a no-op with respect to
// the "listening"/Ok status, and /_status must keep returning 503.
func TestStoppingIsTerminal(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	handler.Listening()
	if !handler.listening {
		t.Fatal("expected listening=true after Listening()")
	}

	handler.Stopping()
	if handler.listening || !handler.stopping {
		t.Fatalf("after Stopping(): listening=%v stopping=%v, want false/true", handler.listening, handler.stopping)
	}

	// A timed reload firing mid-drain must not resurrect healthy state.
	handler.Listening()
	if handler.listening {
		t.Error("Listening() after Stopping() must not set listening=true")
	}
	if !handler.stopping {
		t.Error("stopping must remain true after a late Listening()")
	}

	resp := handler.status(context.Background())
	if resp.Ok {
		t.Error("expected resp.Ok=false after Stopping() even if Listening() fires again")
	}
	if resp.Message != "stopping" {
		t.Errorf("expected message %q, got %q", "stopping", resp.Message)
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, &http.Request{})
	if response.Code != http.StatusServiceUnavailable {
		t.Errorf("expected HTTP 503 after Stopping()+Listening(), got %d", response.Code)
	}
}

// TestReloadingNoOpAfterStopping is a regression test: a timed reload that
// fires after Stopping() must not flip the status back into "reloading".
func TestReloadingNoOpAfterStopping(t *testing.T) {
	handler := newStatusHandler(dummyDial, "", "", "", "")
	handler.Listening()
	handler.Stopping()
	handler.Reloading()
	if handler.reloading {
		t.Error("Reloading() after Stopping() must not set reloading=true")
	}
	if resp := handler.status(context.Background()); resp.Message != "stopping" {
		t.Errorf("expected message %q after Reloading() during stop, got %q", "stopping", resp.Message)
	}
}
