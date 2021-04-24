package certstore

import (
	"fmt"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Prefer CryptoAPI
	fmt.Println("CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG")
	winAPIFlag = 0x00010000
	if status := m.Run(); status != 0 {
		os.Exit(status)
	}

	// Prefer CNG
	fmt.Println("CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG")
	winAPIFlag = 0x00020000
	if status := m.Run(); status != 0 {
		os.Exit(status)
	}

	os.Exit(0)
}
