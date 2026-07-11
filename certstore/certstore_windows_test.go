//go:build windows

package certstore

import (
	"errors"
	"testing"
)

// #include <windows.h>
import "C"

// negativeSecurityStatus converts a Windows HRESULT-style constant (declared as
// an untyped hex constant such as 0x80090008, which does not fit in int32) into
// the signed C.SECURITY_STATUS (typedef LONG, i.e. int32) that the real Windows
// APIs return. The conversion goes through uint32 first so the wrap-around
// happens at runtime rather than triggering a constant-overflow compile error.
func negativeSecurityStatus(v uint32) C.SECURITY_STATUS {
	return C.SECURITY_STATUS(int32(v))
}

func TestCheckStatusUnsupportedHash(t *testing.T) {
	// C.SECURITY_STATUS is `typedef LONG` (int32); NTE_BAD_ALGID (0x80090008)
	// is negative as int32. The old `securityStatus uint64` sign-extended it
	// to 0xFFFFFFFF80090008, so the ErrUnsupportedHash mapping never fired.
	s := negativeSecurityStatus(uint32(NTE_BAD_ALGID))
	if err := checkStatus(s); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("checkStatus(NTE_BAD_ALGID) = %v, want ErrUnsupportedHash", err)
	}
}

func TestCheckStatusSuccess(t *testing.T) {
	if err := checkStatus(C.SECURITY_STATUS(0)); err != nil {
		t.Fatalf("checkStatus(ERROR_SUCCESS) = %v, want nil", err)
	}
}

func TestSecurityStatusErrorFormatting(t *testing.T) {
	// CRYPT_E_NOT_FOUND is not remapped, so Error() formatting is observable.
	// The old uint64 securityStatus sign-extended the value and rendered it as
	// 0xFFFFFFFF80092004; the fix (uint32) renders the true 32-bit code.
	err := checkStatus(negativeSecurityStatus(uint32(CRYPT_E_NOT_FOUND)))
	if got, want := err.Error(), "SECURITY_STATUS 0x80092004"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
