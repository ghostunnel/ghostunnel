/*-
 * Copyright 2025 Square Inc.
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
	"math/rand"
	"net"
	"testing"
)

func TestSelectSRV_EmptyRecords(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	_, err := SelectSRV(nil, rng)
	if err == nil {
		t.Error("expected error for empty records")
	}

	_, err = SelectSRV([]*net.SRV{}, rng)
	if err == nil {
		t.Error("expected error for empty records slice")
	}
}

func TestSelectSRV_SingleRecord(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	record := &net.SRV{
		Priority: 10,
		Weight:   50,
		Port:     443,
		Target:   "example.com",
	}

	selected, err := SelectSRV([]*net.SRV{record}, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if selected != record {
		t.Error("expected same record to be returned")
	}
}

func TestSelectSRV_PriorityOrdering(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	records := []*net.SRV{
		{Priority: 20, Weight: 0, Port: 443, Target: "backup.example.com"},
		{Priority: 10, Weight: 50, Port: 443, Target: "primary.example.com"},
		{Priority: 10, Weight: 50, Port: 443, Target: "primary2.example.com"},
	}

	// Run multiple times to ensure we always select from priority 10
	for i := 0; i < 100; i++ {
		selected, err := SelectSRV(records, rng)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if selected.Priority != 10 {
			t.Errorf("expected priority 10, got %d", selected.Priority)
		}

		if selected.Target == "backup.example.com" {
			t.Error("should never select backup (priority 20) when priority 10 records exist")
		}
	}
}

func TestSelectSRV_WeightDistribution(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	records := []*net.SRV{
		{Priority: 10, Weight: 60, Port: 443, Target: "big.example.com"},
		{Priority: 10, Weight: 20, Port: 443, Target: "small1.example.com"},
		{Priority: 10, Weight: 20, Port: 443, Target: "small2.example.com"},
	}

	// Count selections over many runs
	selectionCounts := make(map[string]int)
	iterations := 1000

	for i := 0; i < iterations; i++ {
		selected, err := SelectSRV(records, rng)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		selectionCounts[selected.Target]++
	}

	// Verify that "big" is selected more often than "small" targets
	// With weights 60:20:20, we expect approximately 60%, 20%, 20% distribution
	bigCount := selectionCounts["big.example.com"]
	small1Count := selectionCounts["small1.example.com"]
	small2Count := selectionCounts["small2.example.com"]

	if bigCount < small1Count || bigCount < small2Count {
		t.Errorf("weighted selection not working: big=%d, small1=%d, small2=%d", bigCount, small1Count, small2Count)
	}

	// Verify we got selections for all targets
	if bigCount == 0 || small1Count == 0 || small2Count == 0 {
		t.Error("expected all targets to be selected at least once")
	}
}

func TestSelectSRV_ZeroWeights(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	records := []*net.SRV{
		{Priority: 10, Weight: 0, Port: 443, Target: "target1.example.com"},
		{Priority: 10, Weight: 0, Port: 443, Target: "target2.example.com"},
		{Priority: 10, Weight: 0, Port: 443, Target: "target3.example.com"},
	}

	// With zero weights, all should be selected with equal probability
	selectionCounts := make(map[string]int)
	iterations := 300

	for i := 0; i < iterations; i++ {
		selected, err := SelectSRV(records, rng)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		selectionCounts[selected.Target]++
	}

	// All should be selected roughly equally (within reasonable variance)
	if len(selectionCounts) != 3 {
		t.Errorf("expected 3 different targets, got %d", len(selectionCounts))
	}
}

func TestSelectSRV_MultiplePriorityLevels(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	records := []*net.SRV{
		{Priority: 30, Weight: 0, Port: 443, Target: "tertiary.example.com"},
		{Priority: 20, Weight: 0, Port: 443, Target: "secondary.example.com"},
		{Priority: 10, Weight: 50, Port: 443, Target: "primary.example.com"},
		{Priority: 10, Weight: 50, Port: 443, Target: "primary2.example.com"},
	}

	// Should always select from priority 10
	for i := 0; i < 100; i++ {
		selected, err := SelectSRV(records, rng)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if selected.Priority != 10 {
			t.Errorf("expected priority 10, got %d", selected.Priority)
		}
	}
}
