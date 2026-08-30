//go:build linux

package collect

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// ClassifyAddr labels an address for the internet zone. Only "global" is
// reachable from outside; everything else cannot be a packet's destination
// when the source is the public internet.
func ClassifyAddr(ip netip.Addr) string {
	switch {
	case ip.IsLoopback():
		return "loopback"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast():
		return "multicast"
	case ip.Is4() && ip.IsPrivate():
		return "private"
	case ip.Is6() && ip.IsPrivate():
		return "ula"
	case ip.IsGlobalUnicast():
		return "global"
	}
	return "other"
}

// Host snapshots interfaces, their addresses and the sysctls that change a
// reachability answer. procRoot is "/proc" in production.
func Host(procRoot string) (facts.Host, []facts.Warning) {
	var warns []facts.Warning
	h := facts.Host{}

	name, err := os.Hostname()
	if err != nil {
		warns = append(warns, facts.Warning{Source: "host", Message: fmt.Sprintf("hostname: %v", err)})
	}
	h.Hostname = name

	// Sysctls are read before interface enumeration so a later failure can
	// never skip them: an unreadable sysctl must always produce a warning,
	// not a silently defaulted false.
	for _, s := range []struct {
		rel string
		dst *bool
	}{
		{"sys/net/ipv4/ip_forward", &h.Sysctls.IPv4Forward},
		{"sys/net/ipv6/conf/all/forwarding", &h.Sysctls.IPv6Forward},
		{"sys/net/ipv6/bindv6only", &h.Sysctls.BindV6Only},
	} {
		val, ok := readSysctlBool(procRoot, s.rel)
		*s.dst = val
		if !ok {
			warns = append(warns, facts.Warning{
				Source: "host", Message: fmt.Sprintf("sysctl %s: could not read, defaulting to false", s.rel),
			})
		}
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		warns = append(warns, facts.Warning{Source: "host", Message: fmt.Sprintf("interfaces: %v", err)})
		return h, warns
	}
	for _, i := range ifaces {
		fi := facts.Interface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0}
		// Per-device forwarding. Deliberately without a warning when it
		// cannot be read: an interface legitimately has no ipv6 conf
		// directory when ipv6 is off, and one can go away mid-read. The
		// value only ever widens what whyopen calls reachable, so a failed
		// read falls back to the global toggle and can never invent
		// forwarding that is not there, which is not true of the global
		// readings above.
		fi.IPv4Forwarding, _ = readSysctlBool(procRoot, "sys/net/ipv4/conf/"+i.Name+"/forwarding")
		fi.IPv6Forwarding, _ = readSysctlBool(procRoot, "sys/net/ipv6/conf/"+i.Name+"/forwarding")
		addrs, err := i.Addrs()
		if err != nil {
			warns = append(warns, facts.Warning{
				Source: "host", Message: fmt.Sprintf("addresses of %s: %v", i.Name, err),
			})
			continue
		}
		for _, a := range addrs {
			pfx, err := netip.ParsePrefix(a.String())
			if err != nil {
				continue
			}
			ip := pfx.Addr()
			fam := "ip"
			if ip.Is6() {
				fam = "ip6"
			}
			fi.Addresses = append(fi.Addresses, facts.Addr{
				IP: ip.String(), Prefix: pfx.Bits(), Family: fam, Scope: ClassifyAddr(ip),
			})
		}
		h.Interfaces = append(h.Interfaces, fi)
	}

	return h, warns
}

// readSysctlBool reads a sysctl file under procRoot and reports whether it
// could be read at all. When ok is false, value is the kernel default
// (false); the caller must surface a warning rather than trusting it as a
// genuine reading.
func readSysctlBool(procRoot, rel string) (value bool, ok bool) {
	b, err := os.ReadFile(filepath.Join(procRoot, rel))
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(b)) == "1", true
}
