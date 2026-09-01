package landlock

import (
	"fmt"
	"strings"
)

type compositeRule struct {
	rules []Rule
}

func (c *compositeRule) String() string {
	descriptions := make([]string, 0, len(c.rules))
	for _, r := range c.rules {
		descriptions = append(descriptions, fmt.Sprintf("%v", r))
	}
	return strings.Join(descriptions, ", ")
}

func (c *compositeRule) compatibleWithConfig(cfg Config) bool {
	for _, r := range c.rules {
		if !r.compatibleWithConfig(cfg) {
			return false
		}
	}
	return true
}

func (c *compositeRule) downgrade(cfg Config) (out Rule, ok bool) {
	cr := new(compositeRule)
	for _, r := range c.rules {
		r, ok := r.downgrade(cfg)
		if !ok {
			return nil, false
		}
		cr.rules = append(cr.rules, r)
	}
	return cr, true
}

func (c *compositeRule) addToRuleset(rulesetFD int, cfg Config) error {
	for _, r := range c.rules {
		err := r.addToRuleset(rulesetFD, cfg)
		if err != nil {
			return err
		}
	}
	return nil
}

// CompositeRule returns a single rule representing multiple rules at
// once.
//
// A composite rule passed to [Config.Restrict] behaves the same as
// passing all sub-rules individually.  Composite rules are not
// strictly necessary in Go-Landlock, but useful for building
// libraries of reusable Landlock rules.
func CompositeRule(rules ...Rule) Rule {
	return &compositeRule{rules: rules}
}
