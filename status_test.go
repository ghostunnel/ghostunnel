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
	"errors"
	"io"
	"net"
	"net/http/httptest"
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
	f, err := os.Open("/dev/null")
	if err != nil {
		panic(err)
	}
	return fakeConn{f}, nil
}

func dummyDialError() (net.Conn, error) {
	return nil, errors.New("fail")
}

func TestStatusHandlerNew(t *testing.T) {
	handler := newStatusHandler(dummyDial)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, nil)

	if response.Code != 503 {
		t.Error("status should return 503 if not yet listening")
	}
}

func TestStatusHandlerListening(t *testing.T) {
	handler := newStatusHandler(dummyDial)
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, nil)

	if response.Code != 200 {
		t.Error("status should return 200 once listening")
	}
}

func TestStatusHandlerListeningBackendDown(t *testing.T) {
	handler := newStatusHandler(dummyDialError)
	response := httptest.NewRecorder()
	handler.Listening()
	handler.ServeHTTP(response, nil)

	if response.Code != 503 {
		t.Error("status should return 503 if backend is down")
	}
}

func TestStatusHandlerReloading(t *testing.T) {
	handler := newStatusHandler(dummyDial)
	response := httptest.NewRecorder()
	handler.Listening()
	handler.Reloading()
	handler.ServeHTTP(response, nil)

	if response.Code != 200 {
		t.Error("status should return 200 during reload")
	}
}
