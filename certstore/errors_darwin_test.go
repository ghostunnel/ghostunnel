//go:build darwin && cgo

package certstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOSStatusErrorType(t *testing.T) {
	// Test the Error() method on osStatus type
	s := errSecItemNotFound
	errStr := s.Error()
	assert.Contains(t, errStr, "OSStatus", "error string should contain OSStatus")
}

// TestOsStatusErrorFunctionNonZero exercises the non-zero branch of
// osStatusError() itself (not just the osStatus.Error() method) by passing
// a known non-success OSStatus value through a thin cgo wrapper.
func TestOsStatusErrorFunctionNonZero(t *testing.T) {
	err := osStatusErrorFromOSStatus(errSecItemNotFound)
	require.Error(t, err, "osStatusError should return non-nil for non-zero status")

	msg := err.Error()
	assert.Contains(t, msg, "OSStatus")
	assert.Contains(t, msg, "-25300") // errSecItemNotFound numeric code

	// Also cover the success branch explicitly to keep both paths exercised
	// in one place.
	assert.NoError(t, osStatusErrorSuccess())
}

// TestBytesToCFDataEmpty exercises the zero-length input branch of
// bytesToCFData(), which is otherwise unreachable from production callers
// (which always pass non-empty data).
func TestBytesToCFDataEmpty(t *testing.T) {
	cdata, err := bytesToCFData([]byte{})
	require.NoError(t, err)
	require.NotEqual(t, nilCFDataRef, cdata)

	// Cleanup via thin cgo wrapper, since cgo is not allowed in _test.go.
	releaseCFData(cdata)
}
