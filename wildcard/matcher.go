/*-
 * Copyright 2018 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package wildcard implements simple wildcard matching meant to be used to
// match URIs and paths against simple patterns. It's less powerful but also
// less error-prone than regular expressions.
//
// We expose functions to build matchers from simple wildcard patterns.  Each
// pattern is a sequence of segments separated by a separator, usually a
// forward slash. Each segment may be a literal string, or a wildcard. We
// support two types of wildcards, a single '*' wildcard and a double '**'
// wildcard.
//
// A single '*' wildcard will match any literal string that does not contain
// the separator. It may occur anywhere between two separators in the pattern.
//
// A double '**' wildcard will match anything, including the separator rune.
// It may only occur at the end of a pattern.
//
// Furthermore, the matcher will consider the separator optional if it occurs
// at the end of a string. This means that the paths "foo/bar" and "foo/bar/"
// are treated as equivalent.
package wildcard

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
)

const (
	defaultSeparator = '/'
)

var (
	errEmptyPattern          = errors.New("input pattern was empty string")
	errInvalidWildcard       = errors.New("wildcard '*' can only appear between two separators")
	errInvalidDoubleWildcard = errors.New("wildcard '**' can only appear at end of pattern")
	errRegexpCompile         = errors.New("unable to compile generated regex (internal bug)")
)

// Matcher represents a compiled pattern that can be matched against a string.
type Matcher interface {
	// Matches checks if the given input matches the compiled pattern.
	Matches(string) bool
}

type regexpMatcher struct {
	// Compiled regular expression for this matcher
	pattern *regexp.Regexp
}

// Compile creates a new Matcher given a pattern, using '/' as the separator.
func Compile(pattern string) (Matcher, error) {
	return CompileWithSeparator(pattern, defaultSeparator)
}

// CompileList creates new Matchers given a list patterns, using '/' as the separator.
func CompileList(patterns []string) ([]Matcher, error) {
	ms := []Matcher{}
	for _, pattern := range patterns {
		m, err := Compile(pattern)
		if err != nil {
			return nil, err
		}
		ms = append(ms, m)
	}
	return ms, nil
}

// MustCompile creates a new Matcher given a pattern, using '/' as the separator,
// and panics if the given pattern was invalid.
func MustCompile(pattern string) Matcher {
	m, err := CompileWithSeparator(pattern, defaultSeparator)
	if err != nil {
		panic(err)
	}
	return m
}

// CompileWithSeparator creates a new Matcher given a pattern and separator rune.
func CompileWithSeparator(pattern string, separator rune) (Matcher, error) {
	// Build regular expression from wildcard pattern
	// - Wildcard '*' should match all chars except forward slash
	// - Wildcard '**' should match all chars, including forward slash
	// All other regex meta chars will need to be quoted

	if pattern == "" {
		return nil, errEmptyPattern
	}

	segments := strings.Split(pattern, string(separator))

	var regex bytes.Buffer
	regex.WriteString("^")

loop:
	for i, segment := range segments {
		switch segment {
		case "*":
			// Segment with wildcard
			regex.WriteString("[^")
			regex.WriteRune(separator)
			regex.WriteString("]+")
		case "**":
			// Segment with double wildcard
			// May only appear at the end of a pattern
			if i != len(segments)-1 {
				return nil, errInvalidDoubleWildcard
			}
			regex.WriteRune('?')
			regex.WriteString(".*$")
			break loop
		default:
			// Segment to match literal string
			if strings.Contains(segment, "*") {
				return nil, errInvalidWildcard
			}
			regex.WriteString(regexp.QuoteMeta(segment))
		}

		// Separate this segment from next one
		regex.WriteRune(separator)

		if i == len(segments)-1 {
			// Final slash should be optional
			// We want "path" and "path/" to match
			regex.WriteString("?$")
		}
	}

	compiled, err := regexp.Compile(regex.String())
	if err != nil {
		return nil, errRegexpCompile
	}

	return regexpMatcher{
		pattern: compiled,
	}, nil
}

// Matches checks if the given input matches the compiled pattern.
func (rm regexpMatcher) Matches(input string) bool {
	return rm.pattern.Match([]byte(input))
}
