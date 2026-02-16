package landlock

// ScopedSet is a set of restrictable IPC scopes.
//
// When the scope is restricted, these IPC operations can not be used
// to communicate with a process in a more privileged sandbox domain
// (e.g. a process in a parent domain or a non-sandboxed process).
type ScopedSet uint64

var scopedNames = []string{
	"abstract_unix_socket",
	"signal",
}

var supportedScoped = ScopedSet((1 << len(scopedNames)) - 1)

func (a ScopedSet) String() string {
	return accessSetString(uint64(a), scopedNames)
}

func (a ScopedSet) isSubset(b ScopedSet) bool {
	return a&b == a
}

func (a ScopedSet) intersect(b ScopedSet) ScopedSet {
	return a & b
}

func (a ScopedSet) isEmpty() bool {
	return a == 0
}

func (a ScopedSet) valid() bool {
	return a.isSubset(supportedScoped)
}
