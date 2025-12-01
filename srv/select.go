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
	"cmp"
	"net"
	"slices"
	"strings"
)

// sortSRV reorders records in place per RFC 2782: ascending by Priority,
// with weighted random ordering applied within each priority group. The
// resulting order is the order targets should be tried for failover.
func sortSRV(records []*net.SRV, intN func(n int) int) {
	slices.SortStableFunc(records, func(a, b *net.SRV) int {
		return cmp.Compare(a.Priority, b.Priority)
	})

	for i := 0; i < len(records); {
		j := i + 1
		for j < len(records) && records[j].Priority == records[i].Priority {
			j++
		}
		weightedShuffle(records[i:j], intN)
		i = j
	}
}

// weightedShuffle reorders a single priority group in place using RFC 2782
// weighted selection: weight-0 records appear first, then records are drawn
// with probability proportional to their weight.
func weightedShuffle(group []*net.SRV, intN func(n int) int) {
	// Weight-0 records appear at the beginning of the unselected list.
	slices.SortStableFunc(group, func(a, b *net.SRV) int {
		switch {
		case (a.Weight == 0) == (b.Weight == 0):
			return 0
		case a.Weight == 0:
			return -1
		default:
			return 1
		}
	})

	sum := 0
	for _, r := range group {
		sum += int(r.Weight)
	}

	// Last position is fixed by elimination, so skip it.
	for start := 0; start < len(group)-1; start++ {
		pick := 0
		if sum > 0 {
			// RFC 2782 specifies target in [0, sum] inclusive, but that
			// gives weight-0 records a 1/(sum+1) chance of being picked
			// first when the running sum is 0. We deviate by using
			// [1, sum] so weight-0 records are only selected when every
			// remaining record has weight 0 (the sum == 0 fall-through).
			target := intN(sum) + 1
			running := 0
			for k, r := range group[start:] {
				running += int(r.Weight)
				if running >= target {
					pick = k
					break
				}
			}
		}

		// Rotate the picked record into the next slot, preserving the
		// weight-0-first ordering of the remaining records.
		if pick != 0 {
			chosen := group[start+pick]
			copy(group[start+1:start+pick+1], group[start:start+pick])
			group[start] = chosen
		}
		sum -= int(group[start].Weight)
	}
}

// BareName strips the _service._proto. prefix from an SRV name like
// "_https._tcp.example.com", returning "example.com". Returns the input
// unchanged if it doesn't have the expected leading underscored components.
func BareName(name string) string {
	parts := strings.SplitN(name, ".", 3)
	if len(parts) < 3 || !strings.HasPrefix(parts[0], "_") || !strings.HasPrefix(parts[1], "_") {
		return name
	}
	return parts[2]
}
