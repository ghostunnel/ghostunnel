//go:build darwin && cgo

package certstore

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// osStatusErrorFromOSStatus lets tests pass an osStatus value (alias of
// C.OSStatus) into osStatusError without importing "C" themselves.
func osStatusErrorFromOSStatus(s osStatus) error {
	return osStatusError(C.OSStatus(s))
}

// osStatusErrorSuccess exercises osStatusError's success branch via the
// errSecSuccess sentinel.
func osStatusErrorSuccess() error {
	return osStatusError(C.errSecSuccess)
}

// releaseCFData releases a CFDataRef returned by bytesToCFData.
func releaseCFData(cdata C.CFDataRef) {
	if cdata != nilCFDataRef {
		C.CFRelease(C.CFTypeRef(cdata))
	}
}
