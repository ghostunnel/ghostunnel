//go:build !windows

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
	"log"
	"os"
	"syscall"

	gsyslog "github.com/hashicorp/go-syslog"
)

var (
	shutdownSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	refreshSignals  = []os.Signal{syscall.SIGHUP, syscall.SIGUSR1}
	syslogFlag      = app.Flag("syslog", "Send logs to syslog instead of stdout (Unix/macOS only).").Bool()
	newSyslogger    = gsyslog.NewLogger
)

func useSystemLog() bool {
	return *syslogFlag
}

func initSystemLogger() error {
	w, err := newSyslogger(gsyslog.LOG_INFO, "DAEMON", "")
	if err != nil {
		return err
	}
	logger = log.New(w, "", log.LstdFlags|log.Lmicroseconds)
	return nil
}

// serviceShutdownChan returns nil on non-Windows platforms. A nil channel
// in a select statement blocks forever, so the service stop case in
// signalHandler is effectively disabled on Unix.
func serviceShutdownChan() <-chan bool {
	return nil
}

func isRunningAsService() bool { return false }

func runAsService() {}

func runServiceCommand(_ string) (bool, error) { return false, nil }
