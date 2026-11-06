//go:build linux

package syscall

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockCreateRuleset creates a ruleset file descriptor with the
// given attributes.
func LandlockCreateRuleset(attr *RulesetAttr, flags int) (fd int, err error) {
	r0, _, e1 := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(attr)), unsafe.Sizeof(*attr), uintptr(flags))
	fd = int(r0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// LandlockGetABIVersion returns the supported Landlock ABI version (starting at 1).
func LandlockGetABIVersion() (version int, err error) {
	r0, _, e1 := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	version = int(r0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// LandlockGetErrata returns the fixed Landlock errata as an integer.
func LandlockGetErrata() (errata int, err error) {
	r0, _, e1 := syscall.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_ERRATA)
	errata = int(r0)
	if errata < 0 {
		err = syscall.Errno(e1)
	}
	return
}

// Landlock rule types.
const (
	RuleTypePathBeneath = unix.LANDLOCK_RULE_PATH_BENEATH
	RuleTypeNetPort     = 2 // TODO: Use it from sys/unix when available.
)

// LandlockAddPathBeneathRule adds a rule of type "path beneath" to
// the given ruleset fd. attr defines the rule parameters. flags must
// currently be 0.
func LandlockAddPathBeneathRule(rulesetFD int, attr *PathBeneathAttr, flags int) error {
	return LandlockAddRule(rulesetFD, RuleTypePathBeneath, unsafe.Pointer(attr), flags)
}

// LandlockAddNetPortRule adds a rule of type "net port" to the given ruleset FD.
// attr defines the rule parameters. flags must currently be 0.
func LandlockAddNetPortRule(rulesetFD int, attr *NetPortAttr, flags int) error {
	return LandlockAddRule(rulesetFD, RuleTypeNetPort, unsafe.Pointer(attr), flags)
}

// LandlockAddRule is the generic landlock_add_rule syscall.
func LandlockAddRule(rulesetFD int, ruleType int, ruleAttr unsafe.Pointer, flags int) (err error) {
	_, _, e1 := syscall.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD), uintptr(ruleType), uintptr(ruleAttr), uintptr(flags), 0, 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}

// LandlockRestrictSelf is the landlock_restrict_self(2) system call.
//
// If the [FlagRestrictSelfTSync] flag is provided in flags, the
// Landlock policy is applied to all threads of the current process,
// and the no_new_privs attribute is also synchronized across all
// threads (if it was set for the current thread).
//
// Without this flag, the policy is only applied to the current OS thread.
//
// If the [FlagRestrictSelfNoNewPrivs] flag is provided in flags, the
// no_new_privs attribute is set by this system call (if and only if
// it succeeds), and does not need to be set with prctl(2) beforehand.
//
// See https://docs.kernel.org/userspace-api/landlock.html#c.sys_landlock_restrict_self
func LandlockRestrictSelf(rulesetFD int, flags uint32) (err error) {
	_, _, e1 := syscall.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), uintptr(flags), 0)
	if e1 != 0 {
		err = syscall.Errno(e1)
	}
	return
}
