package landlock

import ll "github.com/landlock-lsm/go-landlock/landlock/syscall"

type abiInfo struct {
	version                int
	supportedAccessFS      AccessFSSet
	supportedAccessNet     AccessNetSet
	supportedScoped        ScopedSet
	supportedRestrictFlags restrictFlagsSet
}

var abiInfos = []abiInfo{
	{
		version:           0,
		supportedAccessFS: 0,
	},
	{
		version:           1,
		supportedAccessFS: (1 << 13) - 1,
	},
	{
		version:           2,
		supportedAccessFS: (1 << 14) - 1,
	},
	{
		version:           3,
		supportedAccessFS: (1 << 15) - 1,
	},
	{
		version:            4,
		supportedAccessFS:  (1 << 15) - 1,
		supportedAccessNet: (1 << 2) - 1,
	},
	{
		version:            5,
		supportedAccessFS:  (1 << 16) - 1,
		supportedAccessNet: (1 << 2) - 1,
	},
	{
		version:            6,
		supportedAccessFS:  (1 << 16) - 1,
		supportedAccessNet: (1 << 2) - 1,
		supportedScoped:    (1 << 2) - 1,
	},
	{
		version:                7,
		supportedAccessFS:      (1 << 16) - 1,
		supportedAccessNet:     (1 << 2) - 1,
		supportedScoped:        (1 << 2) - 1,
		supportedRestrictFlags: (1 << 3) - 1,
	},
}

func (a abiInfo) asConfig() Config {
	return Config{
		handledAccessFS:  a.supportedAccessFS,
		handledAccessNet: a.supportedAccessNet,
		scoped:           a.supportedScoped,
		flags:            0,
	}
}

// getSupportedABIVersion returns the kernel-supported ABI version.
//
// If the ABI version supported by the kernel is higher than the
// newest one known to go-landlock, the highest ABI version known to
// go-landlock is returned.
func getSupportedABIVersion() abiInfo {
	v, err := ll.LandlockGetABIVersion()
	if err != nil {
		v = 0 // ABI version 0 is "no Landlock support".
	}
	if v >= len(abiInfos) {
		v = len(abiInfos) - 1
	}
	if v >= 6 {
		// Check that the signal scoping bug is fixed,
		// otherwise downgrade to v5.  This should happen only
		// seldomly, as the bugfix was backported to newer
		// versions of the 6.12 LTS kernel.
		errata, err := ll.LandlockGetErrata()
		if err != nil {
			errata = 0 // pretend none fixed
		}
		if (errata & 0x2) == 0 {
			v = 5
		}
	}
	return abiInfos[v]
}
