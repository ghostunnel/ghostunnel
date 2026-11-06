//go:build linux && landlocktsync

package syscall

// AllThreadsLandlockRestrictSelf is a stub for landlocktsync builds.
// It is never called at runtime: with the landlocktsync build tag,
// pre-V8 multi-thread enforcement is disabled, so only the TSYNC path
// is taken.
func AllThreadsLandlockRestrictSelf(rulesetFD int, flags uint32) error {
	panic("unreachable: landlocktsync build disables pre-V8 multi-thread enforcement")
}

// AllThreadsPrctl is a stub for landlocktsync builds.
// It is never called at runtime: with the landlocktsync build tag,
// pre-V8 multi-thread enforcement is disabled, so only the TSYNC path
// is taken.
func AllThreadsPrctl(option int, arg2, arg3, arg4, arg5 uintptr) error {
	panic("unreachable: landlocktsync build disables pre-V8 multi-thread enforcement")
}
