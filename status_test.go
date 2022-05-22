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

// statusTargetWithResponseStatusCode creates a stub status target that returns the status code specified by "code".
func statusTargetWithResponseStatusCode(code int) (statusResponse, int) {
	statusTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	defer statusTarget.Close()

	response := httptest.NewRecorder()
	handler := newStatusHandler(func() (net.Conn, error) {
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
