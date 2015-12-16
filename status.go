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
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer to check if target is up and running
	dial func() (net.Conn, error)
	// Current status
	listening bool
	reloading bool
}

type statusResponse struct {
	Ok            bool      `json:"ok"`
	Status        string    `json:"status"`
	BackendOk     bool      `json:"backend_ok"`
	BackendStatus string    `json:"backend_status"`
	BackendError  string    `json:"backend_error,omitempty"`
	Time          time.Time `json:"time,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Message       string    `json:"message,omitempty"`
	Revision      string    `json:"revision,omitempty"`
	Compiler      string    `json:"compiler,omitempty"`
}

func newStatusHandler(dial func() (net.Conn, error)) *statusHandler {
	return &statusHandler{&sync.Mutex{}, dial, false, false}
}

func (s *statusHandler) Listening() {
	s.mu.Lock()
	s.listening = true
	s.reloading = false
	s.mu.Unlock()
}

func (s *statusHandler) Reloading() {
	s.mu.Lock()
	s.reloading = true
	s.mu.Unlock()
}

func (s *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Time: time.Now(),
	}

	conn, err := s.dial()
	resp.BackendOk = err == nil
	resp.Revision = buildRevision
	resp.Compiler = buildCompiler

	if resp.BackendOk {
		defer conn.Close()
		resp.BackendStatus = "ok"
	} else {
		resp.BackendError = err.Error()
		resp.BackendStatus = "critical"
	}

	s.mu.Lock()
	resp.Ok = s.listening && resp.BackendOk
	if !s.listening {
		resp.Message = "initializing"
	} else if s.reloading {
		resp.Message = "reloading"
	} else {
		resp.Message = "listening"
	}
	s.mu.Unlock()

	if resp.Ok && resp.BackendOk {
		resp.Status = "ok"
	} else {
		resp.Status = "critical"
	}

	hostname, err := os.Hostname()
	if err == nil {
		resp.Hostname = hostname
	}

	out, err := json.Marshal(resp)
	if err != nil {
		panic(err)
	}

	w.Write(out)
}
