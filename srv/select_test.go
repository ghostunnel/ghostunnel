/*-
 * Copyright 2025 Ghostunnel
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

package srv

import (
	"math/rand/v2"
	"net"
	"slices"
	"testing"
)

func newTestIntN(seed uint64) func(n int) int {
	r := rand.New(rand.NewPCG(seed, seed+1))
	return r.IntN
}

func TestSortSRV_Empty(t *testing.T) {
	var records []*net.SRV
	sortSRV(records, newTestIntN(1))
	if len(records) != 0 {
		t.Errorf("expected empty result, got %d records", len(records))
	}
}

func TestSortSRV_Single(t *testing.T) {
	rec := &net.SRV{Priority: 10, Weight: 50, Port: 443, Target: "example.com"}
	records := []*net.SRV{rec}
	sortSRV(records, newTestIntN(1))
	if len(records) != 1 || records[0] != rec {
		t.Errorf("expected single record returned unchanged, got %+v", records)
	}
}

func TestSortSRV_PriorityOrder(t *testing.T) {
	records := []*net.SRV{
		{Priority: 30, Target: "tertiary"},
		{Priority: 10, Weight: 50, Target: "primary-a"},
		{Priority: 20, Target: "secondary"},
		{Priority: 10, Weight: 50, Target: "primary-b"},
	}

	sortSRV(records, newTestIntN(1))

	// Priority 10 records must come first (in either internal order),
	// then 20, then 30.
	wantPriorities := []uint16{10, 10, 20, 30}
	for i, r := range records {
		if r.Priority != wantPriorities[i] {
			t.Errorf("position %d: expected priority %d, got %d (%s)",
				i, wantPriorities[i], r.Priority, r.Target)
		}
	}
}

func TestSortSRV_WeightDistribution(t *testing.T) {
	records := []*net.SRV{
		{Priority: 10, Weight: 60, Target: "big"},
		{Priority: 10, Weight: 20, Target: "small1"},
		{Priority: 10, Weight: 20, Target: "small2"},
	}

	firstCounts := map[string]int{}
	const iterations = 4000
	for i := range iterations {
		input := slices.Clone(records)
		sortSRV(input, newTestIntN(uint64(i)))
		firstCounts[input[0].Target]++
	}

	// With weights 60:20:20, expect "big" to be picked first roughly 60% of
	// the time. Allow generous slack for sampling noise.
	bigPct := float64(firstCounts["big"]) / float64(iterations)
	if bigPct < 0.50 || bigPct > 0.70 {
		t.Errorf("expected 'big' first ~60%% of the time, got %.1f%% (counts: %v)",
			bigPct*100, firstCounts)
	}
}

func TestSortSRV_WeightZeroLast(t *testing.T) {
	records := []*net.SRV{
		{Priority: 10, Weight: 0, Target: "zero-a"},
		{Priority: 10, Weight: 100, Target: "positive"},
		{Priority: 10, Weight: 0, Target: "zero-b"},
	}

	// While any positive-weight record exists, no weight-0 record should
	// ever land in position 0.
	const iterations = 1000
	for i := range iterations {
		input := slices.Clone(records)
		sortSRV(input, newTestIntN(uint64(i)))
		if input[0].Weight == 0 {
			t.Fatalf("iteration %d: weight-0 record %q picked first", i, input[0].Target)
		}
	}
}

func TestBareName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"_https._tcp.example.com", "example.com"},
		{"_xmpp-server._tcp.example.com", "example.com"},
		{"example.com", "example.com"},
		{"_https.example.com", "_https.example.com"},
		{"foo._tcp.example.com", "foo._tcp.example.com"},
		{"_a._b.c.d.e", "c.d.e"},
	}
	for _, tc := range cases {
		if got := BareName(tc.in); got != tc.want {
			t.Errorf("BareName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
