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
	"errors"
	"math/rand"
	"net"
	"sort"
)

// SelectSRV selects a single SRV record from a list of records according to
// RFC 2782 priority and weight rules. Records are sorted by priority (lower
// values first), and from the highest priority group (lowest priority value),
// a record is selected using weighted random selection.
//
// If all records have the same priority, selection is based on weight.
// If all weights are zero, records are selected with equal probability.
// If only one record is provided, it is returned immediately.
//
// Returns an error if the records list is empty.
func SelectSRV(records []*net.SRV, rng *rand.Rand) (*net.SRV, error) {
	if len(records) == 0 {
		return nil, errors.New("no SRV records provided")
	}

	if len(records) == 1 {
		return records[0], nil
	}

	// Sort records by priority (ascending - lower priority values first)
	sorted := make([]*net.SRV, len(records))
	copy(sorted, records)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})

	// Find the highest priority group (lowest priority value)
	highestPriority := sorted[0].Priority
	var priorityGroup []*net.SRV

	for _, record := range sorted {
		if record.Priority == highestPriority {
			priorityGroup = append(priorityGroup, record)
		} else {
			// We've moved past the highest priority group
			break
		}
	}

	// Select from the highest priority group using weighted selection
	return selectByWeight(priorityGroup, rng), nil
}

// selectByWeight performs weighted random selection from a group of SRV records
// with the same priority. If all weights are zero, records are selected with
// equal probability.
func selectByWeight(records []*net.SRV, rng *rand.Rand) *net.SRV {
	if len(records) == 1 {
		return records[0]
	}

	// Calculate total weight
	var totalWeight uint16
	for _, record := range records {
		totalWeight += record.Weight
	}

	// If all weights are zero, select with equal probability
	if totalWeight == 0 {
		return records[rng.Intn(len(records))]
	}

	// Weighted selection: generate random number and find matching record
	randomValue := rng.Intn(int(totalWeight))
	var accumulated uint16

	for _, record := range records {
		accumulated += record.Weight
		if accumulated > uint16(randomValue) {
			return record
		}
	}

	// Fallback (should not reach here, but return last record if it does)
	return records[len(records)-1]
}
