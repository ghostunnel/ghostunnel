//go:build windows

/*-
 * Copyright 2018 Square Inc.
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
	"bytes"
	"log"
	"os"

	"golang.org/x/sys/windows"
)

var (
	shutdownSignals = []os.Signal{os.Interrupt}
	refreshSignals  = []os.Signal{ /* Not supported on Windows */ }
	eventlogFlag    = app.Flag("eventlog", "Send logs to Windows Event Log instead of stdout (Windows only).").Bool()
)

func useSystemLog() bool {
	return *eventlogFlag
}

// eventLogWriter implements io.Writer for the Windows Event Log.
type eventLogWriter struct {
	handle windows.Handle
}

func newEventLogWriter(source string) (*eventLogWriter, error) {
	srcPtr, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return nil, err
	}
	h, err := windows.RegisterEventSource(nil, srcPtr)
	if err != nil {
		return nil, err
	}
	return &eventLogWriter{handle: h}, nil
}

func (w *eventLogWriter) Write(p []byte) (int, error) {
	msg := string(bytes.TrimRight(p, "\n"))
	msgPtr, err := windows.UTF16PtrFromString(msg)
	if err != nil {
		return 0, err
	}
	err = windows.ReportEvent(w.handle, windows.EVENTLOG_INFORMATION_TYPE, 0, 1, 0, 1, 0, &msgPtr, nil)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *eventLogWriter) Close() error {
	return windows.DeregisterEventSource(w.handle)
}

func initSystemLogger() error {
	w, err := newEventLogWriter("ghostunnel")
	if err != nil {
		return err
	}
	logger = log.New(w, "", log.LstdFlags|log.Lmicroseconds)
	return nil
}
