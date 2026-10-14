//go:build !linux

package landlock

import (
	"fmt"
	"syscall"
)

func restrict(c Config, rules ...Rule) error {
	if !c.valid() {
		return fmt.Errorf("unsupported access rights in %v (upgrade go-landlock?): %w", c, syscall.EINVAL)
	}

	if c.bestEffort {
		return nil // Fallback to "nothing"
	}
	return fmt.Errorf("missing kernel Landlock support. Landlock is only supported on Linux")
}
