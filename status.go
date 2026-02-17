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
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/ghostunnel/ghostunnel/proxy"
)

type statusDialer struct {
	dial proxy.DialFunc
}

func (sd statusDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return sd.dial(ctx)
}

type statusHandler struct {
	// Mutex for locking
	mu *sync.Mutex
	// Backend dialer and HTTP client to check if target is up and running
	// - dialer is used for raw TCP status checks
	// - client is used for HTTP status checks if a targetAdress is supplied
	dial                proxy.DialFunc
	client              *http.Client
	command             string
	listenAddress       string
	forwardAddress      string
	statusTargetAddress string
	// Current status
	listening bool
	reloading bool
	stopping  bool
	// Last time we reloaded
	lastReload time.Time
}

type statusResponse struct {
	Ok             bool      `json:"ok"`
	Status         string    `json:"status"`
	ListenAddress  string    `json:"listen_address"`
	ForwardAddress string    `json:"forward_address"`
	BackendOk      bool      `json:"backend_ok"`
	BackendStatus  string    `json:"backend_status"`
	BackendError   string    `json:"backend_error,omitempty"`
	Time           time.Time `json:"time"`
	LastReload     time.Time `json:"last_reload"`
	Hostname       string    `json:"hostname,omitempty"`
	Message        string    `json:"message"`
	Revision       string    `json:"revision"`
	Compiler       string    `json:"compiler"`
}

func newStatusHandler(dial proxy.DialFunc, command, listenAddress, forwardAddress, statusTargetAddress string) *statusHandler {
	client := http.Client{
		Transport: &http.Transport{
			DialContext: statusDialer{dial}.DialContext,
		},
	}
	status := &statusHandler{
		mu:                  &sync.Mutex{},
		dial:                dial,
		client:              &client,
		command:             command,
		listenAddress:       listenAddress,
		forwardAddress:      forwardAddress,
		statusTargetAddress: statusTargetAddress,
		listening:           false,
		reloading:           false,
		stopping:            false,
		lastReload:          time.Time{},
	}
	return status
}

func (s *statusHandler) Listening() {
	systemdNotifyReady()
	systemdNotifyStatus(fmt.Sprintf("listening | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
	s.mu.Lock()
	s.listening = true
	s.reloading = false
	s.mu.Unlock()
}

func (s *statusHandler) Reloading() {
	systemdNotifyReloading()
	systemdNotifyStatus(fmt.Sprintf("reloading | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
	s.mu.Lock()
	s.reloading = true
	s.lastReload = time.Now()
	s.mu.Unlock()
}

func (s *statusHandler) Stopping() {
	systemdNotifyStopping()
	systemdNotifyStatus(fmt.Sprintf("stopping | %s proxying %s => %s", s.command, s.listenAddress, s.forwardAddress))
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
	// we can check that's useful inside the status handler. Right now,
	// this is good enough to report that we're not frozen.
	//nolint:errcheck
	go systemdHandleWatchdog(func() bool { return true }, nil)
}

func (s *statusHandler) status(ctx context.Context) statusResponse {
	resp := statusResponse{
		Time:       time.Now(),
		LastReload: s.lastReload,
	}

	resp.Revision = version
	resp.Compiler = runtime.Version()
	resp.ListenAddress = s.listenAddress
	resp.ForwardAddress = s.forwardAddress

	// Defaults. Will be overridden if checks fail.
	resp.BackendOk = true
	resp.BackendStatus = "ok"

	if err := s.checkBackendStatus(ctx); err != nil {
		resp.BackendOk = false
		resp.BackendError = err.Error()
		resp.BackendStatus = "critical"
	}

	s.mu.Lock()
	resp.Ok = s.listening && resp.BackendOk
	if s.stopping {
		resp.Message = "stopping"
	} else if s.reloading {
		resp.Message = "reloading"
	} else if s.listening {
		resp.Message = "listening"
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

	return resp
}

func (s *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	resp := s.status(r.Context())
	out, err := json.Marshal(resp)
	panicOnError(err)

	w.Header().Set("Content-Type", "application/json")
	if !resp.Ok {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_, _ = w.Write(out)
}

func (s *statusHandler) checkBackendStatus(ctx context.Context) error {
	// If a statusTargetAddress was supplied attempt a HTTP status check.
	// Otherwise, fallback to a raw TCP status check.
	if s.statusTargetAddress != "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.statusTargetAddress, nil)
		if err != nil {
			return err
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("target returned status: %d", resp.StatusCode)
		}
	} else {
		conn, err := s.dial(ctx)
		if err != nil {
			return err
		}
		conn.Close()
	}

	return nil
}
