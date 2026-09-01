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
// [net.Dial].
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
// [net.Listen].  Since Go 1.24, [net.Listen] defaults to Multipath
// TCP, see the discussion in the package documentation.
func BindTCP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetBindTCP,
		port:   port,
	}
}

// BindUDP is a [Rule] which grants the right to bind a UDP socket to
// a given local port.
//
// This access right is available since Landlock V10.
//
// The port 0 has a special meaning: Granting [BindUDP] on port 0
// permits bind(2) calls on port 0, which make the kernel pick an
// arbitrary port from the ephemeral port range.  This also covers the
// implicit "autobind" which the kernel performs when an unbound UDP
// socket gets a remote peer set or sends its first datagram.  Programs
// which handle both [BindUDP] and [ConnectSendUDP] and which use UDP
// sockets that were not already bound before enforcement therefore
// need to grant either [BindUDP](0), or [BindUDP] on a specific port
// which they bind(2) to before connecting or sending.
func BindUDP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetBindUDP,
		port:   port,
	}
}

// ConnectSendUDP is a [Rule] which grants the right to set the remote
// port of a UDP socket to the given port with connect(2), and to send
// datagrams to that remote port with e.g. sendto(2), regardless of any
// destination that was previously set on the socket.
//
// This access right is available since Landlock V10.
//
// Note that setting a remote address or sending a first datagram makes
// the kernel autobind the UDP socket to an ephemeral local source port,
// if it is not already bound.  See [BindUDP] for how to permit that.
func ConnectSendUDP(port uint16) NetRule {
	return NetRule{
		access: ll.AccessNetConnectSendUDP,
		port:   port,
	}
}

func (n NetRule) String() string {
	return fmt.Sprintf("ALLOW %v on port %v", n.access, n.port)
}

func (n NetRule) compatibleWithConfig(c Config) bool {
	return n.access.isSubset(c.handledAccessNet)
}

func (n NetRule) addToRuleset(rulesetFD int, c Config) error {
	if n.access == 0 {
		// Adding this to the ruleset would be a no-op
		// and result in an error.
		return nil
	}
	attr := &ll.NetPortAttr{
		AllowedAccess: uint64(n.access),
		Port:          uint64(n.port),
	}
	return ll.LandlockAddNetPortRule(rulesetFD, attr, 0)
}

func (n NetRule) downgrade(c Config) (out Rule, ok bool) {
	return NetRule{
		access: n.access.intersect(c.handledAccessNet),
		port:   n.port,
	}, true
}

// QuietNetRule is a Rule which marks network ports as "quiet", so
// that denials involving them are kept out of the audit log.
//
// Unlike [NetRule], it does not grant any access rights, and it can
// not be combined with access rights.
type QuietNetRule struct {
	ports []uint16
}

// QuietPorts is a [Rule] which marks the given network ports as
// "quiet": Denials involving these ports are kept out of the audit
// log.
//
// QuietPorts does not grant any access rights, and it only has an
// effect in combination with [Config.QuietAll].  Using it without
// [Config.QuietAll] is an error.
//
// Quieting only affects audit logging.  The affected accesses are
// still denied.
//
// This rule is available since Landlock V10.
func QuietPorts(ports ...uint16) QuietNetRule {
	return QuietNetRule{ports: ports}
}

func (n QuietNetRule) String() string {
	return fmt.Sprintf("QUIET on ports %v", n.ports)
}

func (n QuietNetRule) compatibleWithConfig(c Config) bool {
	// Quieting needs to be enabled with Config.QuietAll().
	return c.quietAll
}

// addRuleFlags returns the flags for the landlock_add_rule(2)
// invocations which add this rule to a ruleset.
//
// It returns 0 if the ruleset has no quiet network access rights:
// The kernel rejects the quiet flag with EINVAL in that case, and the
// rule needs to be left out instead.
func (n QuietNetRule) addRuleFlags(c Config) int {
	if c.quietAccessNet().isEmpty() {
		return 0
	}
	return ll.FlagAddRuleQuiet
}

// downgrade returns the rule unchanged: A quiet rule has no access
// rights to restrict.  If the Config does not support quieting, the
// rule turns into a no-op when it is added to the ruleset.
func (n QuietNetRule) downgrade(c Config) (out Rule, ok bool) {
	return n, true
}

func (n QuietNetRule) addToRuleset(rulesetFD int, c Config) error {
	flags := n.addRuleFlags(c)
	if flags == 0 {
		// Quieting is unavailable under this configuration.
		// Adding a rule without access rights and without the
		// quiet flag would result in an error.
		return nil
	}
	for _, port := range n.ports {
		attr := &ll.NetPortAttr{Port: uint64(port)}
		if err := ll.LandlockAddNetPortRule(rulesetFD, attr, flags); err != nil {
			return fmt.Errorf("populating ruleset for port %v with quieting: %w", port, err)
		}
	}
	return nil
}
