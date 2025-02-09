package proxy

import (
	"math"
	"testing"
)

func TestBytesWithUnit(t *testing.T) {
	cases := []struct {
		n        int64
		expected string
	}{
		{0, "0 bytes"},
		{1, "1 bytes"},
		{1 << 9, "512 bytes"},
		{1<<10 - 1, "1023 bytes"},
		{1 << 10, "1.0 KiB"},
		{1<<10 + 1<<9, "1.5 KiB"},
		{1 << 19, "512.0 KiB"},
		{1 << 20, "1.0 MiB"},
		{1<<20 + 1<<19, "1.5 MiB"},
		{1 << 29, "512.0 MiB"},
		{1 << 30, "1.0 GiB"},
		{1<<30 + 1<<29, "1.5 GiB"},
		{1 << 39, "512.0 GiB"},
		{1 << 40, "1.0 TiB"},
		{1<<40 + 1<<39, "1.5 TiB"},
		{1 << 49, "512.0 TiB"},
		{1 << 50, "1.0 PiB"},
		{1<<50 + 1<<49, "1.5 PiB"},
		{1 << 59, "512.0 PiB"},
		{1 << 60, "1.0 EiB"},
		{1<<60 + 1<<59, "1.5 EiB"},
		{math.MaxInt64, "8.0 EiB"},
	}

	for _, c := range cases {
		result := bytesWithUnit(c.n)
		if result != c.expected {
			t.Errorf("%d: got %s, wanted %s", c.n, result, c.expected)
		}
	}
}
