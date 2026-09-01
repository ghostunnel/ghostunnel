//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"syscall"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

func (r FSRule) addToRuleset(rulesetFD int, c Config) error {
	effectiveAccessFS := r.accessFS
	if !r.enforceSubset {
		effectiveAccessFS = effectiveAccessFS.intersect(c.handledAccessFS)
	}
	if effectiveAccessFS == 0 {
		// Adding this to the ruleset would be a no-op
		// and result in an error.
		return nil
	}
	return addPaths(rulesetFD, r.paths, effectiveAccessFS, 0, r.ignoreMissing)
}

func (r QuietFSRule) addToRuleset(rulesetFD int, c Config) error {
	flags := r.addRuleFlags(c)
	if flags == 0 {
		// Quieting is unavailable under this configuration.
		// Adding a rule without access rights and without the
		// quiet flag would result in an error.
		return nil
	}
	return addPaths(rulesetFD, r.paths, 0, flags, r.ignoreMissing)
}

// addPaths adds one "path beneath" rule per path to the ruleset.
func addPaths(rulesetFd int, paths []string, access AccessFSSet, flags int, ignoreMissing bool) error {
	for _, path := range paths {
		if err := addPath(rulesetFd, path, access, flags); err != nil {
			if ignoreMissing && errors.Is(err, unix.ENOENT) {
				continue // Skip this path.
			}
			return fmt.Errorf("populating ruleset for %q with access %v: %w", path, access, err)
		}
	}
	return nil
}

func addPath(rulesetFd int, path string, access AccessFSSet, flags int) error {
	fd, err := syscall.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer syscall.Close(fd)

	pathBeneath := ll.PathBeneathAttr{
		ParentFd:      fd,
		AllowedAccess: uint64(access),
	}
	err = ll.LandlockAddPathBeneathRule(rulesetFd, &pathBeneath, flags)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			// The ruleset access permissions must be a superset of the ones we restrict to.
			// This should never happen because the call to addPath() ensures that.
			err = fmt.Errorf("inconsistent access rights (using directory access rights on a regular file?): %w", err)
		} else if errors.Is(err, syscall.ENOMSG) && access == 0 {
			err = fmt.Errorf("empty access rights: %w", err)
		} else {
			// Other errors should never happen.
			err = bug(err)
		}
		return fmt.Errorf("landlock_add_rule: %w", err)
	}
	return nil
}
