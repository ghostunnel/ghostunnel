//go:build darwin && cgo

package certstore

/*
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

// osStatusErrorFromOSStatus lets tests pass an osStatusError value (alias of
// C.OSStatus) into newOSStatusError without importing "C" themselves.
func osStatusErrorFromOSStatus(s osStatusError) error {
	return newOSStatusError(C.OSStatus(s))
}

// osStatusErrorSuccess exercises newOSStatusError's success branch via the
// errSecSuccess sentinel.
func osStatusErrorSuccess() error {
	return newOSStatusError(C.errSecSuccess)
}

// releaseCFData releases a CFDataRef returned by bytesToCFData.
func releaseCFData(cdata C.CFDataRef) {
	if cdata != nilCFDataRef {
		C.CFRelease(C.CFTypeRef(cdata))
	}
}
