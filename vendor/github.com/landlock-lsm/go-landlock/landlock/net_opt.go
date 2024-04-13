package landlock

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

type NetRule struct {
	access AccessNetSet
	port   uint16
}

// ConnectTCP is a [Rule] which grants the right to connect a socket
// to a given TCP port.
//
// In Go, the connect(2) operation is usually run as part of
// net.Dial().
func ConnectTCP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetConnectTCP,
		port:   port,
	}
}

// BindTCP is a [Rule] which grants the right to bind a socket to a
// given TCP port.
//
// In Go, the bind(2) operation is usually run as part of
// net.Listen().
func BindTCP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetBindTCP,
		port:   port,
	}
}

func (n NetRule) String() string {
	return fmt.Sprintf("ALLOW %v on TCP port %v", n.access, n.port)
}

func (n NetRule) compatibleWithConfig(c Config) bool {
	return n.access.isSubset(c.handledAccessNet)
}

func (n NetRule) addToRuleset(rulesetFD int, c Config) error {
	flags := 0
	attr := &ll.NetServiceAttr{
		AllowedAccess: uint64(n.access),
		Port:          n.port,
	}
	return ll.LandlockAddNetServiceRule(rulesetFD, attr, flags)
}

func (n NetRule) downgrade(c Config) (out Rule, ok bool) {
	return NetRule{
		access: n.access.intersect(c.handledAccessNet),
		port:   n.port,
	}, true
}
