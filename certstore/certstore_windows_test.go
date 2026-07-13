//go:build windows

package certstore

import (
	"errors"
	"testing"
)

func TestCheckStatusUnsupportedHash(t *testing.T) {
	// NTE_BAD_ALGID (0x80090008) is negative when the Windows APIs return it as
	// a signed 32-bit SECURITY_STATUS. Reinterpreting it as the unsigned
	// securityStatus must not sign-extend, so the mapping to ErrUnsupportedHash
	// still fires. Build the negative int32 at runtime via a uint32 variable to
	// avoid a constant-overflow compile error.
	raw := uint32(NTE_BAD_ALGID)
	if err := checkSecurityStatus(int32(raw)); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("checkSecurityStatus(NTE_BAD_ALGID) = %v, want ErrUnsupportedHash", err)
	}
}

func TestCheckStatusSuccess(t *testing.T) {
	if err := checkSecurityStatus(0); err != nil {
		t.Fatalf("checkSecurityStatus(ERROR_SUCCESS) = %v, want nil", err)
	}
}

func TestSecurityStatusErrorFormatting(t *testing.T) {
	// CRYPT_E_NOT_FOUND is not remapped, so Error() formatting is observable.
	// The old uint64 securityStatus sign-extended the value and rendered it as
	// 0xFFFFFFFF80092004; the fix renders the true 32-bit code.
	raw := uint32(CRYPT_E_NOT_FOUND)
	err := checkSecurityStatus(int32(raw))
	if got, want := err.Error(), "SECURITY_STATUS 0x80092004"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
