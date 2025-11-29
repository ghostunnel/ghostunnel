//go:build linux && !cgo

package landlock

func maybeWorkaroundBug39(c Config, rules []Rule) []Rule {
	// This workaround is only needed for CGO
	return rules
}
