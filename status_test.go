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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
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

func dummyDial() (net.Conn, error) {
	f, err := os.Open(os.DevNull)
	panicOnError(err)
	return fakeConn{f}, nil
}

func dummyDialError() (net.Conn, error) {
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

	err := systemdHandleWatchdog(func() bool { return true }, nil)
	if err == nil {
		t.Error("systemdHandleWatchdog did not handle invalid watchdog settings correctly")
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
		err := systemdHandleWatchdog(func() bool {
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
	handler := newStatusHandler(dummyDial, "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, nil)

	if response.Code != 503 {
		t.Error("status should return 503 if not yet listening")
	}

	if response.Header().Get("Content-Type") != "application/json" {
		t.Error("status response should be application/json")
	}
}

func TestStatusHandlerListeningTCP(t *testing.T) {
	handler := newStatusHandler(dummyDial, "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, nil)

	if response.Code != 200 {
		t.Error("status should return 200 once listening")
	}

	if response.Header().Get("Content-Type") != "application/json" {
		t.Error("status response should be application/json")
	}
}

func TestStatusHandlerListeningBackendDown(t *testing.T) {
	handler := newStatusHandler(dummyDialError, "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, nil)

	if response.Code != 503 {
		t.Error("status should return 503 if backend is down")
	}
}

func TestStatusHandlerReloading(t *testing.T) {
	handler := newStatusHandler(dummyDial, "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.Reloading()
	handler.ServeHTTP(response, nil)

	if response.Code != 200 {
		t.Error("status should return 200 during reload")
	}
}

func TestStatusHandlerStopping(t *testing.T) {
	handler := newStatusHandler(dummyDial, "")
	response := httptest.NewRecorder()
	handler.Listening()
	handler.Stopping()
	handler.ServeHTTP(response, nil)

	if response.Code != 503 {
		t.Error("status should return 503 when stopping")
	}
}

func TestStatusHandlerResponses(t *testing.T) {
	handler := newStatusHandler(dummyDial, "")
	resp := handler.status()
	if resp.Message != "initializing" {
		t.Error("status should say 'initializing' on startup")
	}

	handler.Listening()
	resp = handler.status()
	if resp.Message != "listening" {
		t.Error("status should say 'listening' after startup")
	}

	handler.Reloading()
	resp = handler.status()
	if resp.Message != "reloading" {
		t.Error("status should say 'reloading' when reload initiated")
	}

	handler.Stopping()
	resp = handler.status()
	if resp.Message != "stopping" {
		t.Error("status should say 'stopping' when shutdown initiated")
	}
}

func TestStatusTargetHTTP2XX(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(200)

	if !statusResp.Ok || statusResp.BackendStatus != "ok" || statusRespCode != 200 {
		t.Error("status should return 200 when status backend returns 200")
	}
}

func TestStatusTargetHTTPNon2XX(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(503)

	if statusResp.Ok || statusResp.BackendStatus == "ok" || statusRespCode != 503 {
		t.Error("status should return 503 when status backend returns something other than 200")
	}
}

func TestStatusTargetHTTPWithError(t *testing.T) {
	statusResp, statusRespCode := statusTargetWithResponseStatusCode(-1)

	if statusResp.Ok || statusResp.BackendStatus == "ok" || statusRespCode != 503 {
		t.Error("status should return 503 when status backend returns something other than 200")
	}
}

// statusTargetWithResponseStatusCode creates a stub status target that returns the status code specified by "code".
func statusTargetWithResponseStatusCode(code int) (statusResponse, int) {
	statusTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	defer statusTarget.Close()

	response := httptest.NewRecorder()
	handler := newStatusHandler(func() (net.Conn, error) {
		if code < 0 {
			return nil, errors.New("simulating error when talking to backend")
		}
		u, _ := url.Parse(statusTarget.URL) // NOTE: I tried using statusTarget.Config.Addr instead, but it wasn't set.
		return net.Dial("tcp", fmt.Sprintf("%s:%s", u.Hostname(), u.Port()))
	}, statusTarget.URL)

	req := httptest.NewRequest(http.MethodGet, "/not-empty", nil)
	handler.Listening() // NOTE: required for non-503 backend response code.
	handler.ServeHTTP(response, req)
	res := response.Result()
	defer res.Body.Close()

	data, _ := ioutil.ReadAll(res.Body)

	statusResp := statusResponse{}
	_ = json.Unmarshal(data, &statusResp)

	return statusResp, res.StatusCode
}
