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
	DNAT     *dnat    `json:"-"`
}

// Evaluate returns one verdict per endpoint per address family it serves.
func Evaluate(f facts.Facts, zone Zone) []Verdict {
	var out []Verdict
	for _, ep := range endpoints(f) {
		for _, fam := range familiesFor(ep, f.Host.Sysctls) {
			out = append(out, evaluateOne(f, zone, ep, fam))
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Endpoint.Port != out[j].Endpoint.Port {
			return out[i].Endpoint.Port < out[j].Endpoint.Port
		}
		return out[i].Family < out[j].Family
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
// also accepts IPv4, so one socket gets two independent verdicts.
func familiesFor(e Endpoint, sc facts.Sysctls) []string {
	if e.Family == "ip6" && (e.BindIP == "::" || e.BindIP == "[::]") && !sc.BindV6Only {
		return []string{"ip", "ip6"}
	}
	return []string{e.Family}
}

func evaluateOne(f facts.Facts, zone Zone, ep Endpoint, family string) Verdict {
	v := Verdict{Endpoint: ep, Family: family}

	dst, iface, ok := publicAddr(f, family)
	if !ok {
		v.Result = "filtered"
		v.Reason = fmt.Sprintf("the host has no global unicast %s address, so no packet from the internet can arrive over %s", family, family)
		return v
	}

	src := zone.Src4
	if family == "ip6" {
		src = zone.Src6
	}
	pkt := &Packet{
		Family: family, Proto: ep.Proto,
		Src: src, Dst: dst,
		SrcPort: 41234, DstPort: ep.Port,
		InIface: iface, CtState: "new", DstIsLocal: true,
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
		pkt.OutIface = ifaceFor(f, pre.DNAT.IP)

		hook := "forward"
		if pkt.DstIsLocal {
			hook = "input"
		}
		res, hits := Traverse(f.Ruleset, family, hook, pkt)
		v.Path = append(v.Path, hits...)
		return finish(v, res, fmt.Sprintf("DNAT to %s:%d, then the %s hook", pre.DNAT.IP, pre.DNAT.Port, hook))
	}

	// No DNAT: the packet is delivered locally, so this endpoint only
	// receives it if its bind address covers the destination.
	if !bindCovers(ep.BindIP, dst) {
		v.Result = "filtered"
		v.Reason = fmt.Sprintf("bound to %s, which is not an address a packet from the internet can be sent to (the internet reaches %s)", ep.BindIP, dst)
		return v
	}

	res, hits := Traverse(f.Ruleset, family, "input", pkt)
	v.Path = append(v.Path, hits...)
	return finish(v, res, "delivered locally, so the input hook decides")
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

// publicAddr returns the first global unicast address of the family on an up
// interface, with that interface's name.
func publicAddr(f facts.Facts, family string) (netip.Addr, string, bool) {
	for _, i := range f.Host.Interfaces {
		if !i.Up {
			continue
		}
		for _, a := range i.Addresses {
			if a.Family != family || a.Scope != "global" {
				continue
			}
			if ip, err := netip.ParseAddr(a.IP); err == nil {
				return ip, i.Name, true
			}
		}
	}
	return netip.Addr{}, "", false
}

func isLocal(f facts.Facts, ip netip.Addr) bool {
	for _, i := range f.Host.Interfaces {
		for _, a := range i.Addresses {
			if got, err := netip.ParseAddr(a.IP); err == nil && got == ip {
				return true
			}
		}
	}
	return false
}

// ifaceFor finds the interface whose subnet contains ip, which is how the
// DOCKER chain's oifname matches are resolved.
func ifaceFor(f facts.Facts, ip netip.Addr) string {
	for _, i := range f.Host.Interfaces {
		for _, a := range i.Addresses {
			base, err := netip.ParseAddr(a.IP)
			if err != nil {
				continue
			}
			pfx := netip.PrefixFrom(base, a.Prefix)
			if pfx.Contains(ip) {
				return i.Name
			}
		}
	}
	return ""
}
