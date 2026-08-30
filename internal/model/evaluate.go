package model

import (
	"fmt"
	"net/netip"
	"sort"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// Zone is where the synthetic packet comes from. v1 ships one.
type Zone struct {
	Name string
	Src4 netip.Addr
	Src6 netip.Addr
}

// InternetZone sources from documentation ranges, which are never a local
// address on a sane host, so the packet cannot be mistaken for local traffic.
func InternetZone() Zone {
	return Zone{
		Name: "internet",
		Src4: netip.MustParseAddr("198.51.100.7"),
		Src6: netip.MustParseAddr("2001:db8:ffff::7"),
	}
}

// Endpoint is something that can receive a connection. It comes either from a
// listening socket on the host, or from a Docker publish, because a
// container's socket lives in another network namespace and never appears in
// the host's /proc/net/tcp.
type Endpoint struct {
	Kind   string `json:"kind"` // socket | publish
	Family string `json:"family"`
	Proto  string `json:"proto"`
	BindIP string `json:"bind_ip"`
	Port   uint16 `json:"port"`
	Owner  string `json:"owner,omitempty"`
}

type Verdict struct {
	Endpoint Endpoint `json:"endpoint"`
	Family   string   `json:"family"`
	Result   string   `json:"result"` // reachable | filtered | unknown
	Reason   string   `json:"reason,omitempty"`
	Path     []Hit    `json:"path,omitempty"`
	DNAT     *DNAT    `json:"-"`
}

// Evaluate returns one verdict per endpoint per address family it serves.
func Evaluate(f facts.Facts, zone Zone) []Verdict {
	var out []Verdict
	eps := endpoints(f)
	wildcardIPv4 := wildcardIPv4Keys(eps)
	for _, ep := range eps {
		for _, fam := range familiesFor(ep, f.Host.Sysctls, wildcardIPv4) {
			if f.Ruleset.ReadFailed {
				// The ruleset could not be read at all, so Traverse would
				// see no base chains and default to accept: a confident
				// guess dressed up as a fact. Every endpoint is still
				// listed, honestly marked unknown, before any traversal
				// work happens.
				out = append(out, Verdict{
					Endpoint: ep,
					Family:   fam,
					Result:   "unknown",
					Reason:   "the nftables ruleset could not be read, so no reachability conclusion is possible; whyopen needs root (or CAP_NET_ADMIN) to read it",
				})
				continue
			}
			out = append(out, evaluateOne(f, zone, ep, fam))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Endpoint.Port != b.Endpoint.Port {
			return a.Endpoint.Port < b.Endpoint.Port
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Endpoint.Proto != b.Endpoint.Proto {
			return a.Endpoint.Proto < b.Endpoint.Proto
		}
		if a.Endpoint.BindIP != b.Endpoint.BindIP {
			return a.Endpoint.BindIP < b.Endpoint.BindIP
		}
		return a.Endpoint.Kind < b.Endpoint.Kind
	})
	return out
}

// endpoints merges host sockets and Docker publishes, preferring the publish
// when both describe the same host port, because the container name is the
// better attribution and docker-proxy's own socket is an implementation
// detail.
func endpoints(f facts.Facts) []Endpoint {
	byKey := map[string]Endpoint{}
	key := func(e Endpoint) string {
		return fmt.Sprintf("%s/%s/%s/%d", e.Family, e.Proto, e.BindIP, e.Port)
	}

	for _, s := range f.Sockets {
		e := Endpoint{Kind: "socket", Family: s.Family, Proto: s.Proto,
			BindIP: s.BindIP, Port: s.Port, Owner: socketOwner(s)}
		byKey[key(e)] = e
	}
	for _, c := range f.Docker.Containers {
		for _, p := range c.Publishes {
			fam := "ip"
			if ip, err := netip.ParseAddr(p.HostIP); err == nil && ip.Is6() {
				fam = "ip6"
			}
			e := Endpoint{Kind: "publish", Family: fam, Proto: p.Proto,
				BindIP: p.HostIP, Port: p.HostPort, Owner: c.Name}
			byKey[key(e)] = e // a publish overwrites the docker-proxy socket
		}
	}

	out := make([]Endpoint, 0, len(byKey))
	for _, e := range byKey {
		out = append(out, e)
	}
	return out
}

func socketOwner(s facts.Socket) string {
	switch {
	case s.Unit != "":
		return s.Unit
	case s.Container != "":
		return s.Container
	}
	return s.Process
}

// familiesFor expands the dual-stack case: a :: bind with bind_v6_only=0
// also accepts IPv4, so one socket gets two independent verdicts. This is a
// property of the socket API only: bind_v6_only governs how the kernel binds
// a listening socket, not how a nat rule matches a destination address, so it
// must never apply to a Docker publish. Docker's default "-p 8080:80" emits
// two separate publishes, one for 0.0.0.0 and one for ::; expanding the ::
// entry here would report the same IPv4 exposure as reachable twice.
//
// The global bind_v6_only sysctl only sets the default for a new socket; a
// process can still override it per-socket with IPV6_V6ONLY, which is the
// only way a 0.0.0.0 socket and a :: socket coexist on the same port. When
// that sibling is present, the :: socket must not also expand into an IPv4
// verdict: the real IPv4 exposure is already reported by the 0.0.0.0
// socket, and attributing it to the :: bind instead would both duplicate
// the row and misname the culprit.
func familiesFor(e Endpoint, sc facts.Sysctls, wildcardIPv4 map[string]bool) []string {
	if e.Kind == "socket" && e.Family == "ip6" && (e.BindIP == "::" || e.BindIP == "[::]") && !sc.BindV6Only {
		if wildcardIPv4[fmt.Sprintf("%s/%d", e.Proto, e.Port)] {
			return []string{"ip6"}
		}
		return []string{"ip", "ip6"}
	}
	return []string{e.Family}
}

// wildcardIPv4Keys is built once per Evaluate call so familiesFor does not
// rescan the whole endpoint set for every socket it considers. It records
// every proto/port that already has a genuine 0.0.0.0 (wildcard) IPv4
// socket endpoint.
func wildcardIPv4Keys(eps []Endpoint) map[string]bool {
	keys := make(map[string]bool)
	for _, e := range eps {
		if e.Kind == "socket" && e.Family == "ip" && e.BindIP == "0.0.0.0" {
			keys[fmt.Sprintf("%s/%d", e.Proto, e.Port)] = true
		}
	}
	return keys
}

// pubAddr is one destination the internet can send a packet to: a global
// unicast address together with the interface it lives on.
type pubAddr struct {
	IP    netip.Addr
	Iface string
}

func evaluateOne(f facts.Facts, zone Zone, ep Endpoint, family string) Verdict {
	v := Verdict{Endpoint: ep, Family: family}

	candidates := publicAddrs(f, family)
	if len(candidates) == 0 {
		v.Result = "unknown"
		v.Reason = fmt.Sprintf("the host has no global unicast %s address, so the internet cannot reach it directly here; any exposure would come from an upstream forwarder (a router, cloud load balancer, or provider NAT) that whyopen cannot see", family)
		return v
	}

	var results []Verdict
	for _, c := range candidates {
		if !bindCovers(ep.BindIP, c.IP) {
			continue
		}
		results = append(results, evaluateAtDestination(f, zone, ep, family, c))
	}
	if len(results) == 0 {
		v.Result = "filtered"
		v.Reason = fmt.Sprintf("bound to %s, which does not match any host address the internet can reach", ep.BindIP)
		return v
	}

	// Strongest result wins: an endpoint reachable through any one of the
	// host's public addresses is reachable, full stop. Candidates are
	// produced in a fixed order (interface list, then address list), so
	// picking the first strict improvement keeps the choice deterministic.
	best := results[0]
	for _, r := range results[1:] {
		if resultRank(r.Result) > resultRank(best.Result) {
			best = r
		}
	}
	return best
}

func resultRank(r string) int {
	switch r {
	case "reachable":
		return 2
	case "unknown":
		return 1
	default: // filtered
		return 0
	}
}

func evaluateAtDestination(f facts.Facts, zone Zone, ep Endpoint, family string, c pubAddr) Verdict {
	v := Verdict{Endpoint: ep, Family: family}

	src := zone.Src4
	if family == "ip6" {
		src = zone.Src6
	}
	pkt := &Packet{
		Family: family, Proto: ep.Proto,
		Src: src, Dst: c.IP,
		SrcPort: 41234, DstPort: ep.Port,
		InIface: c.Iface, CtState: "new", DstIsLocal: true,
	}

	pre, hits := Traverse(f.Ruleset, family, "prerouting", pkt)
	v.Path = append(v.Path, hits...)
	if pre.Kind == "unknown" {
		v.Result, v.Reason = "unknown", pre.Reason
		return v
	}
	if pre.Kind == "drop" {
		v.Result, v.Reason = "filtered", pre.Reason
		return v
	}

	if pre.DNAT != nil {
		v.DNAT = pre.DNAT
		pkt.Dst = pre.DNAT.IP
		pkt.DstPort = pre.DNAT.Port
		pkt.DstIsLocal = isLocal(f, pre.DNAT.IP)

		hook := "forward"
		if pkt.DstIsLocal {
			hook = "input"
		} else {
			// The rewritten destination is on another host (a container),
			// so the kernel has to route the packet there, and it only does
			// that when forwarding is enabled for the family. With the
			// sysctl off the routing layer discards the packet before the
			// forward hook runs, so no rule in that hook can make the
			// endpoint reachable however permissive it is.
			if why, on := forwarding(f.Host, c.Iface, family); !on {
				v.Result = "filtered"
				v.Reason = fmt.Sprintf("via %s: DNAT to %s:%d, but %s, so the kernel never routes the packet on and it does not reach the forward hook",
					c.IP, pre.DNAT.IP, pre.DNAT.Port, why)
				return v
			}
			outIface, ok := ifaceFor(f, pre.DNAT.IP)
			if !ok {
				v.Result = "unknown"
				v.Reason = fmt.Sprintf("DNAT target %s is not on any known interface subnet, so the forward path cannot be resolved", pre.DNAT.IP)
				return v
			}
			pkt.OutIface = outIface
		}
		res, hits := Traverse(f.Ruleset, family, hook, pkt)
		v.Path = append(v.Path, hits...)
		return finish(v, res, fmt.Sprintf("via %s: DNAT to %s:%d, then the %s hook", c.IP, pre.DNAT.IP, pre.DNAT.Port, hook))
	}

	// No DNAT: the packet is delivered locally. The caller already
	// established that ep's bind address covers c.IP.
	res, hits := Traverse(f.Ruleset, family, "input", pkt)
	v.Path = append(v.Path, hits...)
	return finish(v, res, fmt.Sprintf("via %s: delivered locally, so the input hook decides", c.IP))
}

// forwarding reports whether the kernel would route a packet that arrived
// on iface onward, and when it would not, says which readings decided
// that so the operator knows every place to look.
//
// Forwarding is a per-device flag and the kernel consults the device the
// packet arrived on, so reading only the global toggle reported a host
// that forwards on one interface as forwarding nothing: the one direction
// an exposure audit must never be wrong in. Writing the global toggle
// propagates to every device and to the default for new ones, so the
// global being on already implies the device's own and either is enough
// here. That also keeps a document from a build that never collected the
// per-interface values reading exactly as it did before.
func forwarding(h facts.Host, iface, family string) (why string, on bool) {
	globalName, globalOn := "net.ipv4.ip_forward", h.Sysctls.IPv4Forward
	perIface := "net.ipv4.conf.%s.forwarding"
	if family == "ip6" {
		globalName, globalOn = "net.ipv6.conf.all.forwarding", h.Sysctls.IPv6Forward
		perIface = "net.ipv6.conf.%s.forwarding"
	}
	if globalOn {
		return "", true
	}
	if iface == "" {
		return globalName + " is 0", false
	}
	ifaceName := fmt.Sprintf(perIface, iface)
	for _, i := range h.Interfaces {
		if i.Name != iface {
			continue
		}
		if (family == "ip6" && i.IPv6Forwarding) || (family != "ip6" && i.IPv4Forwarding) {
			return "", true
		}
	}
	return globalName + " and " + ifaceName + " are both 0", false
}

func finish(v Verdict, res Result, how string) Verdict {
	switch res.Kind {
	case "accept":
		v.Result = "reachable"
		v.Reason = how
	case "drop":
		v.Result = "filtered"
		v.Reason = res.Reason
	default:
		v.Result = "unknown"
		v.Reason = res.Reason
	}
	return v
}

// bindCovers reports whether a listener bound to bindIP receives a packet
// addressed to dst. Wildcard binds cover everything.
func bindCovers(bindIP string, dst netip.Addr) bool {
	if bindIP == "0.0.0.0" || bindIP == "::" || bindIP == "[::]" || bindIP == "" {
		return true
	}
	ip, err := netip.ParseAddr(bindIP)
	if err != nil {
		return false
	}
	return ip == dst || ip.Unmap() == dst.Unmap()
}

// publicAddrs returns every global unicast address of the family on an up
// interface, each paired with that interface's name. A multi-homed host can
// have more than one, and an endpoint bound to a secondary address is only
// reachable through that address, not through whichever one happens to be
// listed first.
func publicAddrs(f facts.Facts, family string) []pubAddr {
	var out []pubAddr
	for _, i := range f.Host.Interfaces {
		if !i.Up {
			continue
		}
		for _, a := range i.Addresses {
			if a.Family != family || a.Scope != "global" {
				continue
			}
			if ip, err := netip.ParseAddr(a.IP); err == nil {
				out = append(out, pubAddr{IP: ip, Iface: i.Name})
			}
		}
	}
	return out
}

func isLocal(f facts.Facts, ip netip.Addr) bool {
	for _, i := range f.Host.Interfaces {
		if !i.Up {
			continue
		}
		for _, a := range i.Addresses {
			if got, err := netip.ParseAddr(a.IP); err == nil && got == ip {
				return true
			}
		}
	}
	return false
}

// ifaceFor finds the interface whose subnet contains ip, which is how the
// DOCKER chain's oifname matches are resolved. The second return reports
// whether a subnet was found at all: a DNAT target that lands on no known
// interface is not a fact whyopen can silently paper over as "no interface",
// because a rule gated on oifname would then simply fail to match and the
// chain's policy would decide, which is indistinguishable from a genuine
// drop.
func ifaceFor(f facts.Facts, ip netip.Addr) (string, bool) {
	for _, i := range f.Host.Interfaces {
		if !i.Up {
			continue
		}
		for _, a := range i.Addresses {
			base, err := netip.ParseAddr(a.IP)
			if err != nil {
				continue
			}
			pfx := netip.PrefixFrom(base, a.Prefix)
			if pfx.Contains(ip) {
				return i.Name, true
			}
		}
	}
	return "", false
}
