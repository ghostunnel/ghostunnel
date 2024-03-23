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
	dial func() (net.Conn, error)
}

func (sd statusDialer) Dial(network, addr string) (net.Conn, error) {
	return sd.dial()
}

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer and HTTP client to check if target is up and running
	// - dialer is used for raw TCP status checks
	// - client is used for HTTP status checks if a targetAdress is supplied
	dial          func() (net.Conn, error)
	client        *http.Client
	targetAddress string
	// Current status
	listening bool
	reloading bool
	stopping  bool
	// Last time we reloaded
	lastReload time.Time
}

type statusResponse struct {
	Ok            bool      `json:"ok"`
	Status        string    `json:"status"`
	BackendOk     bool      `json:"backend_ok"`
	BackendStatus string    `json:"backend_status"`
	BackendError  string    `json:"backend_error,omitempty"`
	Time          time.Time `json:"time"`
	LastReload    time.Time `json:"last_reload,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	Message       string    `json:"message"`
	Revision      string    `json:"revision"`
	Compiler      string    `json:"compiler"`
}

func newStatusHandler(dial func() (net.Conn, error), targetAddress string) *statusHandler {
	client := http.Client{
		Transport: &http.Transport{
			Dial: statusDialer{dial}.Dial,
		},
	}
	status := &statusHandler{&sync.Mutex{}, dial, &client, targetAddress, false, false, false, time.Time{}}
	return status
}

func (s *statusHandler) Listening() {
	systemdNotifyReady()
	s.mu.Lock()
	s.listening = true
	s.reloading = false
	s.mu.Unlock()
}

func (s *statusHandler) Reloading() {
	systemdNotifyReloading()
	s.mu.Lock()
	s.reloading = true
	s.lastReload = time.Now()
	s.mu.Unlock()
}

func (s *statusHandler) Stopping() {
	systemdNotifyStopping()
	s.mu.Lock()
	s.listening = false
	s.reloading = false
	s.stopping = true
	s.mu.Unlock()
}

func (s *statusHandler) HandleWatchdog() {
	// TODO(cs): Figure out a better status check for the watchdog.
	// We don't want the backend check here, because restarting Ghostunnel
	// when the backend is down doesn't help much. But not clear what else
	// we can check that's useful inside the status handler.
	go systemdHandleWatchdog(func() bool { return true })
}

func (s *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := statusResponse{
		Time:       time.Now(),
		LastReload: s.lastReload,
	}

	resp.Revision = version
	resp.Compiler = runtime.Version()

	// Defaults. Will be overridden if checks fail.
	resp.BackendOk = true
	resp.BackendStatus = "ok"

	if err := s.checkBackendStatus(); err != nil {
		resp.BackendOk = false
		resp.BackendError = err.Error()
		resp.BackendStatus = "critical"
	}

	s.mu.Lock()
	resp.Ok = s.listening && resp.BackendOk
	if s.stopping {
		resp.Message = "stopping"
	} else if s.listening {
		resp.Message = "listening"
	} else if s.reloading {
		resp.Message = "reloading"
	} else {
		resp.Message = "initializing"
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
	// If a targetAddress was supplied attempt a HTTP status check.
	// Otherwise, fallback to a raw TCP status check.
	if s.targetAddress != "" {
		resp, err := s.client.Get(s.targetAddress)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("target returned status: %d", resp.StatusCode)
		}
	} else {
		conn, err := s.dial()
		if err != nil {
			return err
		}
		conn.Close()
	}

	return nil
}
