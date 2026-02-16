//go:build darwin

package certstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOSStatusErrorType(t *testing.T) {
	// Test the Error() method on osStatus type
	s := errSecItemNotFound
	errStr := s.Error()
	assert.Contains(t, errStr, "OSStatus", "error string should contain OSStatus")
}
