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

package wildcard

import (
	"fmt"
	"testing"
)

func ExampleCompile_simple() {
	matcher, err := Compile("spiffe://some/*/pattern")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%t\n", matcher.Matches("spiffe://some/test/pattern"))
	fmt.Printf("%t\n", matcher.Matches("spiffe://some/test/example"))
	// Output:
	// true
	// false
}

func ExampleCompile_doubleWildcard() {
	matcher, err := Compile("spiffe://some/*/pattern/**")
	if err != nil {
		panic(err)
	}

	fmt.Printf("%t\n", matcher.Matches("spiffe://some/test/pattern"))
	fmt.Printf("%t\n", matcher.Matches("spiffe://some/test/pattern/that/continues"))
	// Output:
	// true
	// true
}

func testMatches(t *testing.T, pattern string, matches []string, invalids []string) {
	matcher, err := Compile(pattern)
	if err != nil {
		t.Fatalf("bad pattern: '%s' (%s)", pattern, err)
	}

	t.Logf("testing pattern: '%s' => '%s'", pattern, matcher.(regexpMatcher).pattern.String())

	for _, candidate := range matches {
		if !matcher.Matches(candidate) {
			t.Errorf("missed: pattern '%s' didn't match string '%s', but should have", pattern, candidate)
		}
	}

	for _, candidate := range invalids {
		if matcher.Matches(candidate) {
			t.Errorf("bad match: pattern '%s' matched string '%s', but shouldn't have", pattern, candidate)
		}
	}
}

func TestMatchingSimple(t *testing.T) {
	testMatches(t,
		"spiffe://foo/*/bar",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/asdf/bar",
			"spiffe://foo/asdf/bar/",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo/baz/bar/spam",
			"spiff://foo/asdf/bar",
			"spiffe://foox/baz/bar",
			"spiffe://foox/baz/bar/",
			"spiffe://foox/spam/bar",
			"spiffe://foox/spam/bar/",
			"spiffe://foox/asdf/bar",
			"spiffe://foox/asdf/bar/",
			"spiffe://foox/baz/barx",
			"spiffe://foox/baz/barx/",
			"spiffe://foox/spam/barx",
			"spiffe://foox/spam/barx/",
			"spiffe://foox/asdf/barx",
			"spiffe://foox/asdf/barx/",
		})
	testMatches(t,
		"spiffe://*/*/bar",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/asdf/bar",
			"spiffe://foo/asdf/bar/",
			"spiffe://foox/baz/bar",
			"spiffe://foox/baz/bar/",
			"spiffe://foox/spam/bar",
			"spiffe://foox/spam/bar/",
			"spiffe://foox/asdf/bar",
			"spiffe://foox/asdf/bar/",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo/baz/bar/spam",
			"spiff://foo/asdf/bar",
			"spiffe://foox/baz/barx",
			"spiffe://foox/baz/barx/",
			"spiffe://foox/spam/barx",
			"spiffe://foox/spam/barx/",
			"spiffe://foox/asdf/barx",
			"spiffe://foox/asdf/barx/",
		})
	testMatches(t,
		"spiffe://foo/*/*",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/asdf/bar",
			"spiffe://foo/asdf/bar/",
			"spiffe://foo/baz/barx",
			"spiffe://foo/baz/barx/",
			"spiffe://foo/spam/barx",
			"spiffe://foo/spam/barx/",
			"spiffe://foo/asdf/barx",
			"spiffe://foo/asdf/barx/",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo/baz/bar/spam",
			"spiff://foo/asdf/bar",
		})
	testMatches(t,
		"spiffe://*/*/*",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/asdf/bar",
			"spiffe://foo/asdf/bar/",
			"spiffe://foo/baz/barx",
			"spiffe://foo/baz/barx/",
			"spiffe://foo/spam/barx",
			"spiffe://foo/spam/barx/",
			"spiffe://foo/asdf/barx",
			"spiffe://foo/asdf/barx/",
			"spiffe://foox/baz/barx",
			"spiffe://foox/baz/barx/",
			"spiffe://foox/spam/barx",
			"spiffe://foox/spam/barx/",
			"spiffe://foox/asdf/barx",
			"spiffe://foox/asdf/barx/",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo/baz/bar/spam",
			"spiff://foo/asdf/bar",
		})
}

func TestMatchingWithDouble(t *testing.T) {
	testMatches(t,
		"spiffe://foo/*/bar/**",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/baz/bar/spam",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/spam/bar/asdf",
			"spiffe://foo/spam/bar/asdf/qwer",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo//bar/asdf",
			"spiff://foo/asdf/bar",
			"spiffe://foo/baz/barf",
		})
	testMatches(t,
		"spiffe://foo/*/bar/**",
		[]string{
			"spiffe://foo/baz/bar",
			"spiffe://foo/baz/bar/",
			"spiffe://foo/baz/bar/spam",
			"spiffe://foo/spam/bar",
			"spiffe://foo/spam/bar/",
			"spiffe://foo/spam/bar/asdf",
			"spiffe://foo/spam/bar/asdf/qwer",
		},
		[]string{
			"invalid",
			"spiffe://foo/bar",
			"spiffe://foo//bar",
			"spiffe://foo//bar/asdf",
			"spiff://foo/asdf/bar",
			"spiffe://foo/baz/barf",
		})
}

func TestMatchingWithMetaChars(t *testing.T) {
	testMatches(t,
		// The '.' should not be interpreted as a regex char
		"spiffe://foo/./bar",
		[]string{
			"spiffe://foo/./bar",
			"spiffe://foo/./bar/",
		},
		[]string{
			"spiffe://foo/x/bar",
			"spiffe://foo/x/bar/",
		})
	testMatches(t,
		// The '.' should not be interpreted as a regex char
		"spiffe://././.",
		[]string{
			"spiffe://././.",
			"spiffe://./././",
		},
		[]string{
			"spiffe://a/b/c",
			"spiffe://a/b/c/",
		})
	testMatches(t,
		// The meta chars should not be interpreted as a regex
		".+",
		[]string{
			".+",
		},
		[]string{
			"invalid",
		})
}

func TestCompileWithSeparatorMetaChars(t *testing.T) {
	// Each case uses a regex metacharacter as the separator. The pattern
	// is interpreted with that separator, not '/'. A '*' segment must match
	// any literal that does not contain the separator, and literal segments
	// must match exactly.
	tests := []struct {
		name      string
		separator rune
		pattern   string
		matches   []string
		nomatches []string
	}{
		{
			name:      "dot separator",
			separator: '.',
			pattern:   "a.*.b",
			matches: []string{
				"a.foo.b",
				"a.foo.b.",
			},
			nomatches: []string{
				// '.' should NOT act as a regex wildcard.
				"aXfooXb",
				"aXb",
				// '*' segment must not span the separator.
				"a.foo.bar.b",
				// No literal match for empty/missing wildcard segment.
				"a..b",
				// Outright non-matches.
				"a.b",
				"",
			},
		},
		{
			name:      "literal dot separator (no wildcard)",
			separator: '.',
			pattern:   "a.b",
			matches: []string{
				"a.b",
				"a.b.",
			},
			nomatches: []string{
				// '.' should NOT act as a regex wildcard.
				"aXb",
				"a-b",
				"ab",
			},
		},
		{
			name:      "pipe separator",
			separator: '|',
			pattern:   "a|*|b",
			matches: []string{
				"a|foo|b",
				"a|foo|b|",
			},
			nomatches: []string{
				// '|' should NOT act as a regex alternation.
				"a",
				"b",
				"ab",
				"a|b",
				"a|foo|bar|b",
			},
		},
		{
			name:      "plus separator",
			separator: '+',
			pattern:   "a+*+b",
			matches: []string{
				"a+foo+b",
				"a+foo+b+",
			},
			nomatches: []string{
				// '+' should NOT quantify the preceding char.
				"aaab",
				"a+b",
				"a+foo+bar+b",
			},
		},
		{
			name:      "question mark separator",
			separator: '?',
			pattern:   "a?*?b",
			matches: []string{
				"a?foo?b",
				"a?foo?b?",
			},
			nomatches: []string{
				// '?' should NOT make preceding char optional.
				"ab",
				"a?b",
				"a?foo?bar?b",
			},
		},
		{
			name:      "star separator (literal segment only)",
			separator: '*',
			// We cannot use '*' as a wildcard segment when '*' is also the
			// separator (it would just be a separator); test literal segments.
			pattern: "a*b",
			matches: []string{
				"a*b",
				"a*b*",
			},
			nomatches: []string{
				// '*' should NOT quantify the preceding char.
				"aaab",
				"ab",
				"a*b*c",
			},
		},
		{
			name:      "closing bracket separator",
			separator: ']',
			pattern:   "a]*]b",
			matches: []string{
				"a]foo]b",
				"a]foo]b]",
			},
			nomatches: []string{
				// ']' must not break the character class in [^]]+.
				"a]b",
				"a]foo]bar]b",
				"ab",
			},
		},
		{
			name:      "backslash separator",
			separator: '\\',
			pattern:   "a\\*\\b",
			matches: []string{
				"a\\foo\\b",
				"a\\foo\\b\\",
			},
			nomatches: []string{
				// '\' must not introduce an escape sequence.
				"a\\b",
				"a\\foo\\bar\\b",
				"ab",
			},
		},
		{
			name:      "caret separator",
			separator: '^',
			pattern:   "a^*^b",
			matches: []string{
				"a^foo^b",
				"a^foo^b^",
			},
			nomatches: []string{
				// '^' must not negate inside the character class or anchor
				// inappropriately.
				"a^b",
				"a^foo^bar^b",
				"ab",
			},
		},
		{
			// Letter separators must not be interpreted as character-class
			// escapes inside [^...]. In particular, '\d' (digit), '\w' (word),
			// '\s' (space), and their uppercase variants are RE2 escapes; '\b'
			// is not a valid escape at all (would fail to compile).
			name:      "letter separator d (regex \\d escape)",
			separator: 'd',
			pattern:   "xdyd*dxdy",
			matches: []string{
				// wildcard should match any non-'d' string, including digits.
				"xdyd9dxdy",
				"xdydXdxdy",
				"xdyd1234dxdy",
				"xdyd9dxdyd",
			},
			nomatches: []string{
				// wildcard must not span the separator.
				"xdydadbdxdy",
				"xdydXdYdxdy",
				// '*' must match at least one character.
				"xdyddxdy",
				"xdyXdxdy",
			},
		},
		{
			// 'b' as a separator is the worst case: "\b" is not a valid RE2
			// escape, so naively writing "[^\b]+" fails to compile.
			name:      "letter separator b (invalid \\b escape)",
			separator: 'b',
			pattern:   "ab*ba",
			matches: []string{
				"abXba",
				"abXYZba",
				"abXbab",
			},
			nomatches: []string{
				"abba",
				"abbXba",
				"aXa",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := CompileWithSeparator(tc.pattern, tc.separator)
			if err != nil {
				t.Fatalf("CompileWithSeparator(%q, %q) failed: %s", tc.pattern, tc.separator, err)
			}
			t.Logf("pattern=%q sep=%q => regex=%q", tc.pattern, tc.separator, matcher.(regexpMatcher).pattern.String())
			for _, in := range tc.matches {
				if !matcher.Matches(in) {
					t.Errorf("pattern %q (sep %q) did not match %q, but should have", tc.pattern, tc.separator, in)
				}
			}
			for _, in := range tc.nomatches {
				if matcher.Matches(in) {
					t.Errorf("pattern %q (sep %q) matched %q, but should not have", tc.pattern, tc.separator, in)
				}
			}
		})
	}
}

func TestInvalidPatterns(t *testing.T) {
	for _, pattern := range []string{
		"",
		"test://foo*/asdf",
		"test://*foo/asdf",
		"test://**/asdf",
		"**://foo/asdf",
	} {
		_, err := Compile(pattern)
		if err == nil {
			t.Errorf("should reject invalid pattern '%s'", pattern)
		}
	}
}

func TestMustCompile(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("call to MustCompile did not panic with invalid pattern")
		}
	}()

	// Compile with valid pattern
	p := MustCompile("test/**")
	if p == nil {
		t.Error("MustCompile returned nil with valid pattern?")
	}

	// Compile with invalid pattern (should panic)
	MustCompile("**/test")
}

// TestCompileWithSeparator exercises CompileWithSeparator with a non-default '.' separator,
// which is the natural choice for DNS-style hostname matching. The Compile / MustCompile /
// CompileList entry points all hard-code '/', so this is the only path that exercises
// arbitrary separators.
func TestCompileWithSeparator(t *testing.T) {
	// Single-wildcard pattern: matches "anything.example.com" but not multi-segment hosts.
	m, err := CompileWithSeparator("*.example.com", '.')
	if err != nil {
		t.Fatalf("CompileWithSeparator returned error: %s", err)
	}

	matches := []string{
		"foo.example.com",
		"bar.example.com",
		"x.example.com",
	}
	for _, candidate := range matches {
		if !m.Matches(candidate) {
			t.Errorf("expected '%s' to match '*.example.com'", candidate)
		}
	}

	rejects := []string{
		"example.com",
		"foo.bar.example.com", // '*' should NOT cross the '.' separator
		"foo.example.org",
		"",
	}
	for _, candidate := range rejects {
		if m.Matches(candidate) {
			t.Errorf("expected '%s' to NOT match '*.example.com'", candidate)
		}
	}

	// Double-wildcard pattern: '**' at end matches any tail across separators.
	mm, err := CompileWithSeparator("api.example.com.**", '.')
	if err != nil {
		t.Fatalf("CompileWithSeparator returned error: %s", err)
	}
	doubleMatches := []string{
		"api.example.com",
		"api.example.com.v1",
		"api.example.com.v1.users",
	}
	for _, candidate := range doubleMatches {
		if !mm.Matches(candidate) {
			t.Errorf("expected '%s' to match 'api.example.com.**'", candidate)
		}
	}
	if mm.Matches("other.example.com") {
		t.Error("'other.example.com' should not match 'api.example.com.**'")
	}

	// Invalid pattern (wildcard inside a literal segment) should error.
	if _, err := CompileWithSeparator("foo*bar.example.com", '.'); err == nil {
		t.Error("expected error for wildcard inside literal segment")
	}

	// Empty pattern should error.
	if _, err := CompileWithSeparator("", '.'); err == nil {
		t.Error("expected error for empty pattern")
	}
}

// TestTrailingSeparatorNormalization verifies that a single trailing
// separator on the pattern is stripped before compilation, so that
// "foo" and "foo/" accept the same set of inputs.
func TestTrailingSeparatorNormalization(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		matches []string
		nope    []string
	}{
		{
			name:    "trailing separator on literal",
			pattern: "test://foo/bar/",
			matches: []string{
				"test://foo/bar",
				"test://foo/bar/",
			},
			nope: []string{
				"test://foo/bar//",
				"test://foo/baz",
				"test://foo",
				"",
			},
		},
		{
			name:    "no trailing separator on literal",
			pattern: "test://foo/bar",
			matches: []string{
				"test://foo/bar",
				"test://foo/bar/",
			},
			nope: []string{
				"test://foo/bar//",
				"test://foo/baz",
				"test://foo",
				"",
			},
		},
		{
			name:    "trailing separator with wildcard",
			pattern: "test://foo/*/",
			matches: []string{
				"test://foo/baz",
				"test://foo/baz/",
				"test://foo/spam",
				"test://foo/spam/",
			},
			nope: []string{
				"test://foo/baz//",
				"test://foo",
				"test://foo/",
				"test://foo/baz/bar",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			testMatches(t, tc.pattern, tc.matches, tc.nope)
		})
	}
}

// TestTrailingSeparatorEquivalence verifies that "foo" and "foo/"
// compile to equivalent patterns: each accepts exactly the same set
// of inputs (in both directions).
func TestTrailingSeparatorEquivalence(t *testing.T) {
	pairs := []struct {
		a, b string
	}{
		{"foo", "foo/"},
		{"test://foo/bar", "test://foo/bar/"},
		{"test://foo/*/bar", "test://foo/*/bar/"},
		{"test://foo/**", "test://foo/**/"},
	}
	probes := []string{
		"foo",
		"foo/",
		"foo/x",
		"test://foo/bar",
		"test://foo/bar/",
		"test://foo/bar//",
		"test://foo/bar/baz",
		"test://foo/baz/bar",
		"test://foo/baz/bar/",
		"test://foo/x/bar/y",
		"",
	}
	for _, p := range pairs {
		p := p
		t.Run(p.a+"_vs_"+p.b, func(t *testing.T) {
			ma, err := Compile(p.a)
			if err != nil {
				t.Fatalf("compile %q: %s", p.a, err)
			}
			mb, err := Compile(p.b)
			if err != nil {
				t.Fatalf("compile %q: %s", p.b, err)
			}
			for _, probe := range probes {
				if ma.Matches(probe) != mb.Matches(probe) {
					t.Errorf("patterns %q and %q disagree on input %q (%t vs %t)",
						p.a, p.b, probe, ma.Matches(probe), mb.Matches(probe))
				}
			}
		})
	}
}

// TestBareDoubleWildcard verifies that the bare "**" pattern is
// accepted and matches any input, including the empty string and
// strings containing separators. This behaviour is documented as a
// special case rather than emerging from the regex compiler's parse.
func TestBareDoubleWildcard(t *testing.T) {
	matcher, err := Compile("**")
	if err != nil {
		t.Fatalf("bare ** should compile, got error: %s", err)
	}
	inputs := []string{
		"",
		"foo",
		"foo/bar",
		"foo/bar/baz",
		"/",
		"//",
		"a/b/c/d",
		"test://foo/bar",
	}
	for _, in := range inputs {
		if !matcher.Matches(in) {
			t.Errorf("bare ** should match %q but did not", in)
		}
	}
}

func TestCompileList(t *testing.T) {
	// Compile with valid patterns
	ms, err := CompileList([]string{
		"test",
		"test/**",
	})
	if err != nil {
		t.Errorf("CompileList failed with valid patterns: %s", err)
	}
	if len(ms) != 2 {
		t.Errorf("CompileList returned bad number of matchers (%d, wanted 2)", len(ms))
	}

	// Compile with invalid patterns
	ms, err = CompileList([]string{
		"test",
		"**/test",
	})
	if err == nil {
		t.Error("CompileList failed with invalid pattern in input")
	}
	if len(ms) != 0 {
		t.Errorf("CompileList returned bad number of matchers (%d, wanted 0)", len(ms))
	}
}
