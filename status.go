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
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

type statusDialer struct {
	c net.Conn
}

func (sd statusDialer) Dial(network, addr string) (net.Conn, error) {
	return sd.c, nil
}

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer to check if target is up and running
	dial          func() (net.Conn, error)
	targetAddress string
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
	Time          time.Time `json:"time"`
	Hostname      string    `json:"hostname,omitempty"`
	Message       string    `json:"message"`
	Revision      string    `json:"revision"`
	Compiler      string    `json:"compiler"`
}

func newStatusHandler(dial func() (net.Conn, error), targetAddress string) *statusHandler {
	status := &statusHandler{&sync.Mutex{}, dial, targetAddress, false, false}
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

	// Defaults. Will be overriden if checks fail.
	resp.BackendOk = true
	resp.BackendStatus = "ok"

	if err := s.checkBackendStatus(); err != nil {
		resp.BackendOk = false
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
	panicOnError(err)

	w.Header().Set("Content-Type", "application/json")
	if !resp.Ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_, _ = w.Write(out)
}

func (s *statusHandler) checkBackendStatus() error {
	conn, err := s.dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	if s.targetAddress != "" {
		client := http.Client{
			Transport: &http.Transport{
				Dial: statusDialer{conn}.Dial,
			},
		}

		resp, err := client.Get(s.targetAddress)
		if err != nil {
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("target returned status: %d", resp.StatusCode)
		}
	}

	return nil
}
