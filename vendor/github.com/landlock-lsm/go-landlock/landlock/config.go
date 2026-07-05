package landlock

import (
	"errors"
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Access permission sets for filesystem access.
const (
	// The set of access rights that only apply to files.
	accessFile AccessFSSet = ll.AccessFSExecute | ll.AccessFSWriteFile | ll.AccessFSTruncate | ll.AccessFSReadFile

	// The set of access rights associated with read access to files and directories.
	accessFSRead AccessFSSet = ll.AccessFSExecute | ll.AccessFSReadFile | ll.AccessFSReadDir

	// The set of access rights associated with write access to files and directories.
	accessFSWrite AccessFSSet = ll.AccessFSWriteFile | ll.AccessFSRemoveDir | ll.AccessFSRemoveFile | ll.AccessFSMakeChar | ll.AccessFSMakeDir | ll.AccessFSMakeReg | ll.AccessFSMakeSock | ll.AccessFSMakeFifo | ll.AccessFSMakeBlock | ll.AccessFSMakeSym | ll.AccessFSTruncate

	// The set of access rights associated with read and write access to files and directories.
	accessFSReadWrite AccessFSSet = accessFSRead | accessFSWrite
)

// These are Landlock configurations for the currently supported
// Landlock ABI versions, configured to restrict the highest possible
// set of operations possible for each version.
//
// The higher the ABI version, the more operations Landlock will be
// able to restrict.
//
// # Upgrading to V2
//
// Upgrading from V1 to V2 should not break existing programs.
// Programs that need it can now move and link files between
// directories with the "refer" access right.
//
// The [RWFiles] and [RWDirs] helpers do not grant the "refer" right
// automatically, but you can ask for the access right explicitly
// using [FSRule.WithRefer].
//
// # Upgrading to V3
//
// Upgrading from V2 to V3 should not break existing programs,
// as long as they are using [RWPaths] and [RWDirs] to express
// access rights.
//
// Programs that spell out individual access rights might need
// to add the "truncate" access right to the required access
// rights.  Note that the truncation right is often required
// for opening files for writing, because that often does an
// implicit truncation for existing files.
//
// # Upgrading to V4
//
// When upgrading from V3 to V4, the TCP connect() and bind()
// operations (required for [net.Dial] and [net.Listen]) will be
// restricted when using [Config.Restrict] or [Config.RestrictNet].
//
// Note: This only affects "classic" TCP, not Multipath TCP.
// Multipath TCP, which is the default for [net.Listen] since
// Go 1.24, continues to work.
//
// For comprehensive network sandboxing at this ABI level, we
// recommend using additional sandboxing mechanisms.
//
// # Upgrading to V5
//
// When upgrading from V4 to V5, if you use [Config.Restrict] or
// [Config.RestrictPaths], IOCTL operations on device files are now
// restricted.  A small list of common IOCTLs continues to be
// permitted and is listed in the [Kernel Documentation about Access Rights].
//
// The [RWFiles] and [RWDirs] helpers do not grant IOCTL rights
// automatically, but you can ask for the access right explicitly
// using [FSRule.WithIoctlDev].
//
// # Upgrading to V6
//
// When upgrading from V5 to V6, the following operations are newly
// restricted if you are using [Config.Restrict] or
// [Config.RestrictScoped]:
//
//   - Abstract UNIX Domain Socket connections that are reaching out to
//     a server outside of the enforced Landlock domain.
//   - UNIX signals that are signaling a program which is running outside
//     of the enforced Landlock domain.
//
// # Upgrading to V7
//
// Upgrading from V6 to V7 is safe.
//
// With ABI V7, the following methods can be newly used to influence
// audit logging of Landlock denials:
//
//   - [Config.DisableLoggingForOriginatingProcess]
//   - [Config.EnableLoggingForSubprocesses]
//   - [Config.DisableLoggingForSubdomains]
//
// It is safe to use these in combination with [Config.BestEffort],
// also on Linux systems that only support older Landlock ABIs.
//
// When one of these logging flags is set but [Config.BestEffort] is
// omitted, you are asserting that you are running on a kernel that
// supports ABI V7+, and you will get an error at restriction time if
// the kernel does not support that.
//
// # Upgrading to V8
//
// Upgrading from V7 to V8 is safe.
//
// ABI V8 adds an under-the-hood improvement for multithreaded
// Landlock enforcement, which is used by Go-Landlock whenever it is
// available.  The [landlock.V8] configuration preset restricts the
// same operations as [landlock.V7].
//
// # Upgrading to V9
//
// When upgrading from V8 to V9, if you use [Config.Restrict] or
// [Config.RestrictPaths], connect(2) and sendmsg(2) calls on pathname
// UNIX domain sockets (see unix(7)) are now restricted.  This only
// affects connections to UNIX server sockets that were created
// outside of the enforced Landlock domain.  Newly created UNIX
// servers within the same Landlock domain continue to be accessible.
//
// The [RWFiles] and [RWDirs] helpers do not grant the "resolve unix"
// access right automatically, but you can ask for the access right
// explicitly using [FSRule.WithResolveUnix].
//
// [Kernel Documentation about Access Rights]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
var (
	// Landlock V1 support (basic file operations).
	V1 = abiInfos[1].asConfig()
	// Landlock V2 support (V1 + file reparenting between different directories)
	V2 = abiInfos[2].asConfig()
	// Landlock V3 support (V2 + file truncation)
	V3 = abiInfos[3].asConfig()
	// Landlock V4 support (V3 + networking)
	V4 = abiInfos[4].asConfig()
	// Landlock V5 support (V4 + ioctl on device files)
	V5 = abiInfos[5].asConfig()
	// Landlock V6 support (V5 + IPC scopes for signals and
	// Abstract UNIX Domain Sockets (see unix(7)))
	V6 = abiInfos[6].asConfig()
	// Landlock V7 support (V6 + logging support)
	V7 = abiInfos[7].asConfig()
	// Landlock V8 support (V7 + thread synchronization)
	V8 = abiInfos[8].asConfig()
	// Landlock V9 support (V8 + restricting connect(2) and sendmsg(2)
	// on pathname UNIX domain sockets)
	V9 = abiInfos[9].asConfig()
)

// v0 denotes "no Landlock support". Only used internally.
var v0 = Config{}

// The Landlock configuration describes the desired set of
// landlockable operations to be restricted and the constraints on it
// (e.g., best effort mode).
//
// It is recommended to use one of the preset configurations such as
// [landlock.V9], which restrict the full set of access rights
// available at this Landlock ABI version.
type Config struct {
	handledAccessFS  AccessFSSet
	handledAccessNet AccessNetSet
	scoped           ScopedSet
	flags            restrictFlagsSet
	bestEffort       bool
}

// NewConfig creates a new Landlock configuration with the given parameters.
//
// Passing an AccessFSSet, AccessNetSet or ScopedSet will set these as
// the set of filesystem/network/scoped operations to restrict when
// enabling Landlock. The sets need to stay within the bounds of what
// Go-Landlock supports.  (If you are getting an error, you might need
// to upgrade to a newer version of Go-Landlock.)
//
// Example:
//
//	cfg, err := NewConfig(AccessFSSet(llsyscall.AccessFSExecute))
func NewConfig(args ...any) (*Config, error) {
	// Implementation note: This factory is written with future
	// extensibility in mind. Only specific types are supported as
	// input, but in the future more might be added.
	//
	// This constructor ensures that callers can't construct
	// invalid Config values.
	var c Config
	for _, arg := range args {
		switch arg := arg.(type) {
		case AccessFSSet:
			if !c.handledAccessFS.isEmpty() {
				return nil, errors.New("only one AccessFSSet may be provided")
			}
			if !arg.valid() {
				return nil, errors.New("unsupported AccessFSSet value; upgrade go-landlock?")
			}
			c.handledAccessFS = arg
		case AccessNetSet:
			if !c.handledAccessNet.isEmpty() {
				return nil, errors.New("only one AccessNetSet may be provided")
			}
			if !arg.valid() {
				return nil, errors.New("unsupported AccessNetSet value; upgrade go-landlock?")
			}
			c.handledAccessNet = arg
		case ScopedSet:
			if !c.scoped.isEmpty() {
				return nil, errors.New("only one ScopedSet may be provided")
			}
			if !arg.valid() {
				return nil, errors.New("unsupported ScopedSet value; upgrade go-landlock?")
			}
			c.scoped = arg
		default:
			return nil, fmt.Errorf("unknown argument %v; only AccessFSSet-type argument is supported", arg)
		}
	}
	return &c, nil
}

// MustConfig is like NewConfig but panics on error.
func MustConfig(args ...any) Config {
	c, err := NewConfig(args...)
	if err != nil {
		panic(err)
	}
	return *c
}

// String builds a human-readable representation of the Config.
func (c Config) String() string {
	abi := abiInfo{version: -1} // invalid
	for i := len(abiInfos) - 1; i >= 0; i-- {
		a := abiInfos[i]
		if c.compatibleWithABI(a) {
			abi = a
		}
	}

	fsDesc := c.handledAccessFS.String()
	if abi.supportedAccessFS == c.handledAccessFS && c.handledAccessFS != 0 {
		fsDesc = "all"
	}

	netDesc := c.handledAccessNet.String()
	if abi.supportedAccessNet == c.handledAccessNet && c.handledAccessNet != 0 {
		netDesc = "all"
	}

	scopedDesc := c.scoped.String()
	if abi.supportedScoped == c.scoped && c.scoped != 0 {
		scopedDesc = "all"
	}

	extra := ""
	if c.flags != 0 {
		extra += fmt.Sprintf(" (flags: %s)", c.flags.String())
	}
	if c.bestEffort {
		extra += " (best effort)"
	}

	var version string
	if abi.version < 0 {
		version = "V???"
	} else {
		version = fmt.Sprintf("V%v", abi.version)
	}

	return fmt.Sprintf("{Landlock %v; FS: %v; Net: %v; Scoped: %v%v}", version, fsDesc, netDesc, scopedDesc, extra)
}

// BestEffort returns a config that will opportunistically enforce
// the strongest rules it can, up to the given ABI version, working
// with the level of Landlock support available in the running kernel.
//
// Warning: A best-effort call to RestrictPaths() will succeed without
// error even when Landlock is not available at all on the current kernel.
func (c Config) BestEffort() Config {
	cfg := c
	cfg.bestEffort = true
	return cfg
}

// DisableLoggingForOriginatingProcess disables logging of denied
// accesses originating from the thread creating the Landlock domain,
// as well as its children, as long as they continue running the same
// executable code (i.e., without an intervening execve(2) call).
//
// This is intended for programs that execute unknown code without
// invoking execve(2), such as script interpreters.  Programs that
// only sandbox themselves should not set this flag, so users can be
// notified of unauthorized access attempts via system logs.
//
// Requires a Linux kernel that supports Landlock ABI V7 or higher.
// In combination with [Config.BestEffort], the logging option will be
// omitted on older kernels and not result in an error.
func (c Config) DisableLoggingForOriginatingProcess() Config {
	cfg := c
	cfg.flags |= ll.FlagRestrictSelfLogSameExecOff
	return cfg
}

// EnableLoggingForSubprocesses enables logging of denied accesses
// after an execve(2) call, providing visibility into unauthorized
// access attempts by newly executed programs within the created
// Landlock domain.
//
// This flag is recommended only when all potential executables in the
// domain are expected to comply with the access restrictions, as
// excessive audit log entries could make it more difficult to
// identify critical events.
//
// Requires a Linux kernel that supports Landlock ABI V7 or higher.
// In combination with [Config.BestEffort], the logging option will be
// omitted on older kernels and not result in an error.
func (c Config) EnableLoggingForSubprocesses() Config {
	cfg := c
	cfg.flags |= ll.FlagRestrictSelfLogNewExecOn
	return cfg
}

// DisableLoggingForSubdomains disables logging of denied accesses
// originating from nested Landlock domains created by the caller or
// its descendants. This flag should be set according to runtime
// configuration, not hardcoded, to avoid suppressing important
// security events.
//
// It is useful for container runtimes or sandboxing tools that may
// launch programs which themselves create Landlock domains and could
// otherwise generate excessive logs.  Unlike
// [DisableLoggingForOriginatingProcess], this affects future nested
// domains, not the one being created.
//
// Requires a Linux kernel that supports Landlock ABI V7 or higher.
// In combination with [Config.BestEffort], the logging option will be
// omitted on older kernels and not result in an error.
func (c Config) DisableLoggingForSubdomains() Config {
	cfg := c
	cfg.flags |= ll.FlagRestrictSelfLogSubdomainsOff
	return cfg
}

// RestrictPaths restricts all goroutines to only "see" the files
// provided as inputs. After this call successfully returns, the
// goroutines will only be able to use files in the ways as they were
// specified in advance in the call to RestrictPaths.
//
// Example: The following invocation will restrict all goroutines so
// that they can only read from /usr, /bin and /tmp, and only write to
// /tmp:
//
//	err := landlock.V9.RestrictPaths(
//	    landlock.RODirs("/usr", "/bin"),
//	    landlock.RWDirs("/tmp"),
//	)
//	if err != nil {
//	    log.Fatalf("landlock.V9.RestrictPaths(): %v", err)
//	}
//
// RestrictPaths returns an error if any of the given paths does not
// denote an actual directory or file, or if Landlock can't be enforced
// using the desired ABI version constraints.
//
// RestrictPaths also sets the "no new privileges" flag for all OS
// threads managed by the Go runtime.
//
// # Restrictable access rights
//
// The notions of what "reading" and "writing" mean are limited by what
// the selected Landlock version supports.
//
// Calling RestrictPaths with a given Landlock ABI version will
// inhibit all future calls to the access rights supported by this ABI
// version, unless the accessed path is in a file hierarchy that is
// specifically allow-listed for a specific set of access rights.
//
// The overall set of operations that RestrictPaths can restrict are:
//
// For reading:
//
//   - Executing a file (V1+)
//   - Opening a file with read access (V1+)
//   - Opening a directory or listing its content (V1+)
//
// For writing:
//
//   - Opening a file with write access (V1+)
//   - Truncating file contents (V3+)
//
// For directory manipulation:
//
//   - Removing an empty directory or renaming one (V1+)
//   - Removing (or renaming) a file (V1+)
//   - Creating (or renaming or linking) a character device (V1+)
//   - Creating (or renaming) a directory (V1+)
//   - Creating (or renaming or linking) a regular file (V1+)
//   - Creating (or renaming or linking) a UNIX domain socket (V1+)
//   - Creating (or renaming or linking) a named pipe (V1+)
//   - Creating (or renaming or linking) a block device (V1+)
//   - Creating (or renaming or linking) a symbolic link (V1+)
//   - Renaming or linking a file between directories (V2+)
//
// Future versions of Landlock will be able to inhibit more operations.
// Quoting the Landlock documentation:
//
//	It is currently not possible to restrict some file-related
//	actions accessible through these syscall families: chdir(2),
//	stat(2), flock(2), chmod(2), chown(2), setxattr(2), utime(2),
//	ioctl(2), fcntl(2), access(2). Future Landlock evolutions will
//	enable to restrict them.
//
// The access rights are documented in more depth in the
// [Kernel Documentation about Access Rights].
//
// # Helper functions for selecting access rights
//
// These helper functions help selecting common subsets of access rights:
//
//   - [RODirs] selects access rights in the group "for reading".
//     In V1, this means reading files, listing directories and executing files.
//   - [RWDirs] selects access rights in the group "for reading", "for writing" and
//     "for directory manipulation". This grants the full set of access rights which are
//     available within the configuration.
//   - [ROFiles] is like [RODirs], but does not select directory-specific access rights.
//     In V1, this means reading and executing files.
//   - [RWFiles] is like [RWDirs], but does not select directory-specific access rights.
//     In V1, this means reading, writing and executing files.
//
// The [PathAccess] rule lets callers define custom subsets of these
// access rights. AccessFSSets permitted using [PathAccess] must be a
// subset of the [AccessFSSet] that the Config restricts.
//
// To restrict multiple types of access rights at the same time, use
// the more generic [Config.Restrict].
//
// [Kernel Documentation about Access Rights]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#access-rights
func (c Config) RestrictPaths(rules ...Rule) error {
	// clear out everything but filesystem access
	c = Config{
		handledAccessFS: c.handledAccessFS,
		flags:           c.flags,
		bestEffort:      c.bestEffort,
	}
	return restrict(c, rules...)
}

// RestrictNet restricts network access in all goroutines.
//
// Using Landlock V4, this function restricts the use of bind(2) and
// connect(2) for TCP ports, unless those TCP ports are specifically
// permitted using these rules:
//
//   - [ConnectTCP] permits connect(2) operations to a given TCP port.
//   - [BindTCP] permits bind(2) operations on a given TCP port.
//
// These network access rights are documented in more depth in the
// [Kernel Documentation about Network flags].
//
// The restrictions do not currently work with Multipath TCP, which is
// the default for [net.Listen] since Go 1.24.  See the discussion in
// the package-level documentation.
//
// Landlock's network sandboxing support is still incomplete as of
// Landlock ABI v9 and we recommend using additional sandboxing
// mechanisms to augment it.
//
// To restrict multiple types of access rights at the same time, use
// the more generic [Config.Restrict].
//
// [Kernel Documentation about Network flags]: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html#network-flags
func (c Config) RestrictNet(rules ...Rule) error {
	// clear out everything but network access
	c = Config{
		handledAccessNet: c.handledAccessNet,
		flags:            c.flags,
		bestEffort:       c.bestEffort,
	}
	return restrict(c, rules...)
}

// RestrictScoped restricts scoped IPC access in all goroutines.
//
// Starting with Landlock V6, this restricts the use of IPC mechanisms
// like signals and abstract UNIX domain sockets, when talking to
// processes in more privileged Landlock domains.
//
// To restrict multiple types of access rights at the same time, use
// the more generic [Config.Restrict].
func (c Config) RestrictScoped() error {
	// clear out everything but scoped operations
	c = Config{
		scoped:     c.scoped,
		flags:      c.flags,
		bestEffort: c.bestEffort,
	}
	return restrict(c)
}

// Restrict restricts all types of access rights which are
// restrictable with the Config.
//
// Using Landlock V9, this is equivalent to calling all of
// [Config.RestrictPaths], [Config.RestrictNet] and
// [Config.RestrictScoped] with the respective subset of rule
// arguments that apply to them.
//
// In future Landlock versions, this function might restrict
// additional types of access rights which are specified in the [Config].
func (c Config) Restrict(rules ...Rule) error {
	return restrict(c, rules...)
}

// PathOpt is a deprecated alias for [Rule].
//
// Deprecated: This alias is only kept around for backwards
// compatibility and will disappear with the next major release.
type PathOpt = Rule

// compatibleWith is true if c is compatible to work at the given Landlock ABI level.
func (c Config) compatibleWithABI(abi abiInfo) bool {
	return (c.handledAccessFS.isSubset(abi.supportedAccessFS) &&
		c.handledAccessNet.isSubset(abi.supportedAccessNet) &&
		c.scoped.isSubset(abi.supportedScoped)) &&
		c.flags.isSubset(abi.supportedRestrictFlags)
}

// restrictTo returns a config that is a subset of c and which is compatible with the given ABI.
func (c Config) restrictTo(abi abiInfo) Config {
	return Config{
		handledAccessFS:  c.handledAccessFS.intersect(abi.supportedAccessFS),
		handledAccessNet: c.handledAccessNet.intersect(abi.supportedAccessNet),
		scoped:           c.scoped.intersect(abi.supportedScoped),
		flags:            c.flags.intersect(abi.supportedRestrictFlags),
		bestEffort:       true,
	}
}
