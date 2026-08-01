/*-
 * Copyright 2026 Ghostunnel
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

import "testing"

// BenchmarkMatcherMatches measures Matcher.Matches, which runs once per
// configured --allow-uri/--verify-uri pattern on every TLS handshake (via
// auth.ACL's URI SAN check) until a pattern matches. Matchers are compiled
// once at startup, so only the match itself is on the hot path; the inputs
// are SPIFFE-style URIs, the common use case for URI ACLs. The no-match
// cases matter as much as the matches: for a denied peer (or a matcher list
// where a later entry matches), every preceding pattern runs to rejection.
func BenchmarkMatcherMatches(b *testing.B) {
	const (
		matchingInput = "spiffe://cluster.local/ns/prod/sa/bench-client"
		// Same prefix as the patterns below, so rejection scans the input
		// rather than failing on the first byte.
		nonMatchingInput = "spiffe://cluster.local/ns/staging/sa/other-client/extra"
	)

	for _, tc := range []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"literal-match", "spiffe://cluster.local/ns/prod/sa/bench-client", matchingInput, true},
		{"literal-no-match", "spiffe://cluster.local/ns/prod/sa/bench-client", nonMatchingInput, false},
		{"single-wildcard-match", "spiffe://cluster.local/ns/*/sa/*", matchingInput, true},
		{"single-wildcard-no-match", "spiffe://cluster.local/ns/*/sa/*", nonMatchingInput, false},
		{"double-wildcard-match", "spiffe://cluster.local/**", matchingInput, true},
		{"double-wildcard-no-match", "spiffe://other.cluster/**", nonMatchingInput, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			m := MustCompile(tc.pattern)
			if got := m.Matches(tc.input); got != tc.want {
				b.Fatalf("Matches(%q) = %v before measurement, want %v", tc.input, got, tc.want)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				_ = m.Matches(tc.input)
			}
		})
	}
}
