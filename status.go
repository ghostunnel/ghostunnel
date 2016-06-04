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
	"os/exec"
	"runtime"
	"sync"
	"time"
)

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer to check if target is up and running
	dial func() (net.Conn, error)
	// Child process (if chain-execed, may be nil)
	child *exec.Cmd
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
	ChildPid      *int      `json:"child_pid,omitempty"`
	Time          time.Time `json:"time"`
	Hostname      string    `json:"hostname,omitempty"`
	Message       string    `json:"message"`
	Revision      string    `json:"revision"`
	Compiler      string    `json:"compiler"`
}

func newStatusHandler(dial func() (net.Conn, error), child *exec.Cmd) *statusHandler {
	status := &statusHandler{&sync.Mutex{}, dial, child, false, false}
	return status
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

	resp.Revision = version
	resp.Compiler = runtime.Version()

	conn, err := s.dial()
	resp.BackendOk = err == nil

	if resp.BackendOk {
		conn.Close()
		resp.BackendStatus = "ok"
	} else {
		resp.BackendError = err.Error()
		resp.BackendStatus = "critical"
	}

	if s.child != nil && s.child.Process != nil {
		resp.ChildPid = &s.child.Process.Pid
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
	panicOnError(err)

	if !resp.Ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	w.Write(out)
}
