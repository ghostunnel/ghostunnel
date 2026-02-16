package landlock

import (
	"strings"
)

// restrictFlagsSet is a set of logging directives.
type restrictFlagsSet uint32

var flagNames = []string{
	"log_same_exec_off",
	"log_new_exec_on",
	"log_subdomains_off",
}

func (a restrictFlagsSet) String() string {
	var b strings.Builder
	for i, flagName := range flagNames {
		if a&(1<<i) == 0 {
			continue
		}
		if b.Len() > 1 {
			b.WriteByte(',')
		}
		b.WriteString(flagName)
	}
	return b.String()
}

func (a restrictFlagsSet) isSubset(b restrictFlagsSet) bool {
	return a&b == a
}

func (a restrictFlagsSet) intersect(b restrictFlagsSet) restrictFlagsSet {
	return a & b
}
