// +build linux

package main

import (
	"os"
	"syscall"
)

func sysProcAttr() *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{
		Setpgid: true, // Create new process group
	}
	if os.Getpid() != 1 {
		// Send TERM to child if parent exits
		// See https://github.com/golang/go/issues/9263 for explanation on PID restriction
		attr.Pdeathsig = syscall.SIGTERM
	}
	return attr
}
