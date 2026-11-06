//go:build linux && !landlocktsync

package syscall

import (
	"syscall"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/psx"
)

// AllThreadsLandlockRestrictSelf enforces the given ruleset on all OS
// threads belonging to the current process.
//
// For Landlock ABI V8 and higher, we recommend using
// [LandlockRestrictSelf] with the [FlagRestrictSelfTSync] flag instead.
func AllThreadsLandlockRestrictSelf(rulesetFD int, flags uint32) (err error) {
	_, _, e1 := psx.Syscall3(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), uintptr(flags), 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// AllThreadsPrctl is like unix.Prctl, but gets applied on all OS threads at the same time.
func AllThreadsPrctl(option int, arg2, arg3, arg4, arg5 uintptr) (err error) {
	_, _, e1 := psx.Syscall6(unix.SYS_PRCTL, uintptr(option), uintptr(arg2), uintptr(arg3), uintptr(arg4), uintptr(arg5), 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}
