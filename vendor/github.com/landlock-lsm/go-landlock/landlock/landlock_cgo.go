//go:build linux && cgo

package landlock

import (
	"fmt"
	"os"

	"github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// maybeWorkaroundBug39 adds an extra rule in the case that we are
// affected by https://github.com/landlock-lsm/go-landlock/issues/39.
//
// libpsx 1.2.72+ attempts to list the directory /proc/$PID/task, just
// after doing the Landlock enforcement system call on each thread.
// We are silently adding that directory so that the enforcement will
// return a success.
func maybeWorkaroundBug39(c Config, rules []Rule) []Rule {
	const readDir = syscall.AccessFSReadDir
	if c.handledAccessFS.intersect(readDir).isEmpty() {
		return rules
	}
	path := fmt.Sprintf("/proc/%v/task", os.Getpid())
	extraRule := PathAccess(readDir, path)
	return append(rules, extraRule)
}
