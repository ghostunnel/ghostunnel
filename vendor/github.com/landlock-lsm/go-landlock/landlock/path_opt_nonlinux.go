//go:build !linux

package landlock

import "errors"

func (r FSRule) addToRuleset(rulesetFD int, c Config) error {
	return errors.New("Landlock is only supported on Linux")
}

func (r QuietFSRule) addToRuleset(rulesetFD int, c Config) error {
	return errors.New("Landlock is only supported on Linux")
}
