package model

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// hostFacts is a minimal host: one public interface, one Docker bridge.
func hostFacts() facts.Facts {
	return facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Host: facts.Host{
			Hostname: "testbox",
			Interfaces: []facts.Interface{
				{Name: "eth0", Index: 2, Up: true, Addresses: []facts.Addr{
					{IP: "203.0.113.10", Prefix: 24, Family: "ip", Scope: "global"},
				}},
				{Name: "br-abc", Index: 3, Up: true, Addresses: []facts.Addr{
					{IP: "172.20.0.1", Prefix: 16, Family: "ip", Scope: "private"},
				}},
			},
			Sysctls: facts.Sysctls{IPv4Forward: true, BindV6Only: false},
		},
	}
}

// ufwFilter is UFW's shape: input and forward both default deny, with the
// conntrack accept that cannot match a fresh SYN.
func ufwFilter() facts.Table {
	ctAccept := facts.Rule{Handle: 10, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "conntrack", Decoded: true,
			Conntrack: &facts.ConntrackInfo{MatchesState: true, States: []string{"established", "related"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	return facts.Table{Family: "ip", Name: "filter", Chains: []facts.Chain{
		{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{ctAccept}},
		{Name: "FORWARD", Base: true, Hook: "forward", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{ctAccept, jumpRule(11, "DOCKER")}},
		{Name: "DOCKER"},
	}}
}

// dockerNAT publishes hostIP:port to 172.20.0.2:port via DNAT.
func dockerNAT(hostIP string, port uint16) facts.Table {
	return dockerNATTo(hostIP, port, "172.20.0.2")
}

// dockerNATTo is dockerNAT with the DNAT rewrite target made explicit, so a
// test can point the DNAT at an address that lands on no known interface
// subnet.
func dockerNATTo(hostIP string, port uint16, targetIP string) facts.Table {
	hostHex := map[string]string{"0.0.0.0": "", "203.0.113.10": "cb00710a", "127.0.0.1": "7f000001", "192.0.2.55": "c0000237"}[hostIP]
	exprs := []facts.Expr{}
	if hostHex != "" {
		exprs = append(exprs,
			facts.Expr{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
			facts.Expr{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: hostHex}},
		)
	}
	exprs = append(exprs,
		facts.Expr{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		facts.Expr{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1,
			Data: string([]byte{"0123456789abcdef"[port>>12&0xf], "0123456789abcdef"[port>>8&0xf], "0123456789abcdef"[port>>4&0xf], "0123456789abcdef"[port&0xf]})}},
		facts.Expr{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "DNAT", Decoded: true,
			DNAT: &facts.DNATInfo{MinIP: targetIP, MaxIP: targetIP, MinPort: port, MaxPort: port}}},
	)
	return facts.Table{Family: "ip", Name: "nat", Chains: []facts.Chain{
		{Name: "PREROUTING", Base: true, Hook: "prerouting", Priority: -100, Policy: "accept",
			Rules: []facts.Rule{jumpRule(20, "DOCKER")}},
		{Name: "DOCKER", Rules: []facts.Rule{{Handle: 21, Exprs: exprs}}},
	}}
}

// The canonical trap: UFW is enabled and denies by default, yet a container
// published on 0.0.0.0 is reachable, because the packet is DNAT'd in
// prerouting and then handled in forward, where DOCKER accepts it. UFW's
// input chain is never consulted.
func TestPublishOnAllInterfacesIsReachableDespiteUFW(t *testing.T) {
	f := hostFacts()
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)} // DOCKER accepts
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("0.0.0.0", 5432)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c1", Name: "db-1",
		Publishes: []facts.Publish{{HostIP: "0.0.0.0", HostPort: 5432,
			ContainerIP: "172.20.0.2", ContainerPort: 5432, Proto: "tcp"}},
	}}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
	}
	v := vs[0]
	if v.Result != "reachable" {
		t.Fatalf("result = %q (%s), want reachable", v.Result, v.Reason)
	}
	if v.DNAT == nil || v.DNAT.Port != 5432 {
		t.Fatalf("expected the verdict to carry the DNAT rewrite, got %+v", v.DNAT)
	}
	if v.Endpoint.Owner != "db-1" {
		t.Fatalf("owner = %q, want the container name", v.Endpoint.Owner)
	}
	var sawForward bool
	for _, h := range v.Path {
		if h.Hook == "forward" {
			sawForward = true
		}
		if h.Hook == "input" {
			t.Fatalf("the input hook must not appear in the path of a DNAT'd packet: %+v", v.Path)
		}
	}
	if !sawForward {
		t.Fatalf("expected the forward hook in the path: %+v", v.Path)
	}
}

// The same publish bound to loopback is not reachable, and the reason must
// say why rather than just "filtered".
func TestPublishOnLoopbackIsNotReachable(t *testing.T) {
	f := hostFacts()
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)}
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("127.0.0.1", 5432)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c1", Name: "db-1",
		Publishes: []facts.Publish{{HostIP: "127.0.0.1", HostPort: 5432,
			ContainerIP: "172.20.0.2", ContainerPort: 5432, Proto: "tcp"}},
	}}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "filtered" {
		t.Fatalf("got %+v, want a single filtered verdict", vs)
	}
	if vs[0].Reason == "" {
		t.Fatalf("a filtered verdict must explain itself")
	}
}

// A host socket on 0.0.0.0 behind UFW's drop policy is filtered, and one
// explicitly accepted is reachable.
func TestHostSocketFollowsTheInputChain(t *testing.T) {
	f := hostFacts()
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "filtered" {
		t.Fatalf("got %+v, want filtered by the input drop policy", vs)
	}

	filter := ufwFilter()
	filter.Chains[0].Rules = append(filter.Chains[0].Rules, acceptRule(13))
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter}}
	vs = Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "reachable" {
		t.Fatalf("got %+v, want reachable", vs)
	}
	if vs[0].Endpoint.Owner != "ssh.service" {
		t.Fatalf("owner = %q", vs[0].Endpoint.Owner)
	}
}

// A :: bind with bind_v6_only=0 is one socket and two verdicts.
func TestDualStackBindProducesTwoVerdicts(t *testing.T) {
	f := hostFacts()
	f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
		facts.Addr{IP: "2001:db8::10", Prefix: 64, Family: "ip6", Scope: "global"})
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{{Family: "ip6", Proto: "tcp", BindIP: "::", Port: 8081, Process: "node"}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 2 {
		t.Fatalf("got %d verdicts, want one per family: %+v", len(vs), vs)
	}
	fams := map[string]bool{}
	for _, v := range vs {
		fams[v.Family] = true
	}
	if !fams["ip"] || !fams["ip6"] {
		t.Fatalf("families = %v, want both ip and ip6", fams)
	}
}

// With no global address of that family at all, the tool has no basis for
// claiming the port is closed: an upstream forwarder (provider NAT, a home
// router's port forward, a cloud load balancer) is invisible to it, and
// "filtered" would be a safety claim it cannot support. It must say unknown.
func TestNoGlobalAddressOfThatFamilyIsExplained(t *testing.T) {
	f := hostFacts() // IPv4 only
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{{Family: "ip6", Proto: "tcp", BindIP: "::1", Port: 9000}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "unknown" || vs[0].Reason == "" {
		t.Fatalf("got %+v, want an explained unknown verdict", vs)
	}
}

// A host with only private addresses (e.g. behind provider NAT) yields the
// same unknown verdict for the same reason: no global address of the family
// exists, so whyopen cannot see whether an upstream forwarder exposes it.
func TestHostWithOnlyPrivateAddressesYieldsUnknown(t *testing.T) {
	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Host: facts.Host{
			Hostname: "testbox",
			Interfaces: []facts.Interface{
				{Name: "eth0", Index: 2, Up: true, Addresses: []facts.Addr{
					{IP: "10.0.0.5", Prefix: 24, Family: "ip", Scope: "private"},
				}},
			},
			Sysctls: facts.Sysctls{IPv4Forward: true, BindV6Only: false},
		},
	}
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "unknown" || vs[0].Reason == "" {
		t.Fatalf("got %+v, want an explained unknown verdict", vs)
	}
}

// RULING 15: a socket bound to a secondary public address must not be
// reported filtered just because publicAddrs happens to list a different
// address first. It is genuinely reachable when the chain accepts.
func TestSocketOnSecondaryAddressIsReachable(t *testing.T) {
	f := hostFacts()
	f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
		facts.Addr{IP: "192.0.2.55", Prefix: 24, Family: "ip", Scope: "global"})
	filter := ufwFilter()
	filter.Chains[0].Rules = append(filter.Chains[0].Rules, acceptRule(13))
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter}}
	f.Sockets = []facts.Socket{{Family: "ip", Proto: "tcp", BindIP: "192.0.2.55", Port: 8443, Unit: "svc.service"}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "reachable" {
		t.Fatalf("got %+v, want reachable via the secondary address", vs)
	}
}

// RULING 15: the same is true when a Docker publish's DNAT rule is written
// against a secondary address rather than the first one whyopen happens to
// enumerate.
func TestPublishOnSecondaryAddressIsReachable(t *testing.T) {
	f := hostFacts()
	f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
		facts.Addr{IP: "192.0.2.55", Prefix: 24, Family: "ip", Scope: "global"})
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)} // DOCKER accepts
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("192.0.2.55", 9090)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c2", Name: "app",
		Publishes: []facts.Publish{{HostIP: "192.0.2.55", HostPort: 9090,
			ContainerIP: "172.20.0.3", ContainerPort: 9090, Proto: "tcp"}},
	}}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "reachable" {
		t.Fatalf("got %+v, want reachable via the secondary address", vs)
	}
}

// RULING 16: a DNAT target that lands on no known interface subnet must not
// silently resolve to an empty out interface: that would let an oifname
// gated rule silently fail to match and the chain's policy decide instead,
// which is indistinguishable from a genuine drop. It must be unknown.
func TestDNATTargetOnNoKnownSubnetIsUnknown(t *testing.T) {
	f := hostFacts()
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)}
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNATTo("0.0.0.0", 6000, "10.99.0.5")}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c3", Name: "orphan",
		Publishes: []facts.Publish{{HostIP: "0.0.0.0", HostPort: 6000,
			ContainerIP: "10.99.0.5", ContainerPort: 6000, Proto: "tcp"}},
	}}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "unknown" || vs[0].Reason == "" {
		t.Fatalf("got %+v, want an explained unknown verdict", vs)
	}
}

// RULING 17: endpoints() ranges a map, so ordering must be forced by a total
// comparator, not left to depend on map iteration order. Run Evaluate many
// times over endpoints that tie on port and family (tcp and udp, plus a
// third bound to loopback) to catch a shuffle.
func TestOrderingIsStableAcrossRuns(t *testing.T) {
	f := hostFacts()
	filter := ufwFilter()
	filter.Chains[0].Rules = append(filter.Chains[0].Rules, acceptRule(13))
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter}}
	f.Sockets = []facts.Socket{
		{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 53, Unit: "dns-tcp.service"},
		{Family: "ip", Proto: "udp", BindIP: "0.0.0.0", Port: 53, Unit: "dns-udp.service"},
		{Family: "ip", Proto: "udp", BindIP: "127.0.0.1", Port: 53, Unit: "dns-local.service"},
	}

	var want []string
	for i := 0; i < 200; i++ {
		vs := Evaluate(f, InternetZone())
		got := make([]string, len(vs))
		for j, v := range vs {
			got[j] = v.Family + "/" + v.Endpoint.Proto + "/" + v.Endpoint.BindIP
		}
		if want == nil {
			want = got
			continue
		}
		if len(got) != len(want) {
			t.Fatalf("run %d: got %d verdicts, want %d: %v", i, len(got), len(want), got)
		}
		for j := range got {
			if got[j] != want[j] {
				t.Fatalf("run %d: ordering changed: got %v, want %v", i, got, want)
			}
		}
	}
}

// RULING 18: bind_v6_only governs a listening socket's API, not how a nat
// rule matches a destination address. Docker's default "-p 8080:80" shape
// emits two publishes, one for 0.0.0.0 and one for ::; the :: one must not
// be expanded across both families, or the IPv4 exposure is reported twice.
func TestDockerDefaultDualEntryPublishYieldsOneIPv4Verdict(t *testing.T) {
	f := hostFacts()
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)}
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("0.0.0.0", 8080)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c4", Name: "web",
		Publishes: []facts.Publish{
			{HostIP: "0.0.0.0", HostPort: 8080, ContainerIP: "172.20.0.2", ContainerPort: 80, Proto: "tcp"},
			{HostIP: "::", HostPort: 8080, ContainerIP: "172.20.0.2", ContainerPort: 80, Proto: "tcp"},
		},
	}}}

	vs := Evaluate(f, InternetZone())
	var ipCount int
	for _, v := range vs {
		if v.Family == "ip" {
			ipCount++
		}
	}
	if ipCount != 1 {
		t.Fatalf("got %d ip verdicts, want exactly 1: %+v", ipCount, vs)
	}
}

// RULING 22: familiesFor expanded a :: bind across both families whenever
// bind_v6_only=0, without checking for a sibling 0.0.0.0 socket on the same
// proto/port. Two such sockets can only coexist via a per-socket
// IPV6_V6ONLY override, which the global sysctl cannot describe; the real
// IPv4 exposure belongs to the 0.0.0.0 socket, not the :: one, so expanding
// the :: socket too fabricates a duplicate IPv4 verdict attributed to the
// wrong bind.
func TestDualStackSocketWithIPv4SiblingIsNotDuplicated(t *testing.T) {
	f := hostFacts()
	f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
		facts.Addr{IP: "2001:db8::10", Prefix: 64, Family: "ip6", Scope: "global"})
	filter := ufwFilter()
	filter.Chains[0].Rules = append(filter.Chains[0].Rules, acceptRule(13))
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter}}
	f.Sockets = []facts.Socket{
		{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
		{Family: "ip6", Proto: "tcp", BindIP: "::", Port: 22, Process: "sshd-v6"},
	}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 2 {
		t.Fatalf("got %d verdicts, want exactly 2 (one per family): %+v", len(vs), vs)
	}
	var ipv4, ipv6 *Verdict
	for i := range vs {
		switch vs[i].Family {
		case "ip":
			ipv4 = &vs[i]
		case "ip6":
			ipv6 = &vs[i]
		}
	}
	if ipv4 == nil || ipv6 == nil {
		t.Fatalf("want one ip and one ip6 verdict, got %+v", vs)
	}
	if ipv4.Endpoint.BindIP != "0.0.0.0" {
		t.Fatalf("ipv4 verdict attributed to bind %q, want the real 0.0.0.0 socket", ipv4.Endpoint.BindIP)
	}
	if ipv6.Endpoint.BindIP != "::" {
		t.Fatalf("ipv6 verdict attributed to bind %q, want ::", ipv6.Endpoint.BindIP)
	}
}

// RULING 23: an unreadable ruleset must never produce a confident verdict.
// With no base chains to traverse, Traverse defaults to accept, which
// finish() turns into a false "reachable" -- exactly the guess this tool
// exists to prevent.
func TestUnreadableRulesetYieldsUnknownForEveryEndpoint(t *testing.T) {
	f := hostFacts()
	f.Ruleset = facts.Ruleset{ReadFailed: true}
	f.Sockets = []facts.Socket{
		{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
	}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
	}
	if vs[0].Result != "unknown" || vs[0].Reason == "" {
		t.Fatalf("got %+v, want an explained unknown verdict when the ruleset could not be read", vs[0])
	}
}

// The same host with the ruleset readable behaves exactly as before.
func TestReadableRulesetStillEvaluatesNormally(t *testing.T) {
	f := hostFacts()
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{
		{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
	}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "filtered" {
		t.Fatalf("got %+v, want filtered by the input drop policy, same as before this ruling", vs)
	}
}

// I5: net.ipv4.ip_forward and net.ipv6.conf.all.forwarding were collected
// and read nowhere. A DNAT'd packet aimed at a container is routed, not
// delivered locally, so with forwarding off the kernel discards it before
// the forward hook runs and no rule there can make the port reachable.
func TestDNATWithForwardingDisabledIsFiltered(t *testing.T) {
	f := hostFacts()
	f.Host.Sysctls.IPv4Forward = false
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)} // DOCKER accepts
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("0.0.0.0", 5432)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c1", Name: "db-1",
		Publishes: []facts.Publish{{HostIP: "0.0.0.0", HostPort: 5432,
			ContainerIP: "172.20.0.2", ContainerPort: 5432, Proto: "tcp"}},
	}}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
	}
	if vs[0].Result != "filtered" {
		t.Fatalf("result = %q (%s), want filtered: the kernel does not forward", vs[0].Result, vs[0].Reason)
	}
	if !strings.Contains(vs[0].Reason, "net.ipv4.ip_forward") {
		t.Fatalf("reason = %q, want it to name the disabled sysctl", vs[0].Reason)
	}
}

// The same host with forwarding on is the canonical reachable case, so the
// sysctl is doing the deciding and nothing else changed.
func TestDNATWithForwardingEnabledStillReachable(t *testing.T) {
	f := hostFacts() // IPv4Forward: true
	filter := ufwFilter()
	filter.Chains[2].Rules = []facts.Rule{acceptRule(12)}
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter, dockerNAT("0.0.0.0", 5432)}}
	f.Docker = facts.Docker{Available: true, Containers: []facts.Container{{
		ID: "c1", Name: "db-1",
		Publishes: []facts.Publish{{HostIP: "0.0.0.0", HostPort: 5432,
			ContainerIP: "172.20.0.2", ContainerPort: 5432, Proto: "tcp"}},
	}}}

	if vs := Evaluate(f, InternetZone()); len(vs) != 1 || vs[0].Result != "reachable" {
		t.Fatalf("got %+v, want reachable", vs)
	}
}

// L1 end to end: with the two rules UFW ships in ufw6-before-input, an IPv6
// verdict must resolve rather than come back unknown. On the reference host
// all six IPv6 verdicts were blamed on "rt type 0 counter drop".
func TestUFWIPv6BeforeInputRulesDoNotPoisonTheVerdict(t *testing.T) {
	f := hostFacts()
	f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
		facts.Addr{IP: "2001:db8::10", Prefix: 64, Family: "ip6", Scope: "global"})

	xtMatch := func(name string) facts.Expr {
		return facts.Expr{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: name}}
	}
	drop := facts.Expr{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}}
	accept := facts.Expr{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}

	f.Ruleset = facts.Ruleset{Tables: []facts.Table{{
		Family: "ip6", Name: "filter", Chains: []facts.Chain{{
			Name: "ufw6-before-input", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{
				{Handle: 52, Exprs: []facts.Expr{xtMatch("rt"), drop}},
				{Handle: 53, Exprs: []facts.Expr{xtMatch("icmp6"), xtMatch("hl"), accept}},
				{Handle: 54, Exprs: []facts.Expr{
					{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
					{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "0016"}},
					accept,
				}},
			},
		}},
	}}}
	f.Sockets = []facts.Socket{
		{Family: "ip6", Proto: "tcp", BindIP: "::", Port: 22, Unit: "ssh.service"},
		{Family: "ip6", Proto: "tcp", BindIP: "::", Port: 9000, Process: "app"},
	}

	for _, v := range Evaluate(f, InternetZone()) {
		if v.Family != "ip6" {
			continue
		}
		if v.Result == "unknown" {
			t.Fatalf("port %d came back unknown (%s); UFW's rt and hl rules must resolve", v.Endpoint.Port, v.Reason)
		}
		want := "filtered"
		if v.Endpoint.Port == 22 {
			want = "reachable"
		}
		if v.Result != want {
			t.Fatalf("port %d = %q (%s), want %q", v.Endpoint.Port, v.Result, v.Reason, want)
		}
	}
}

// Ledger minor: nothing durable covered the mixed multi-candidate case. A
// multi-homed host produces one result per public address, and the strongest
// must win whichever position it lands in, with the surviving reason
// belonging to the candidate that actually won.
func TestStrongestCandidateWinsAndKeepsItsOwnReason(t *testing.T) {
	acceptOn := func(addrHex string) facts.Rule {
		return facts.Rule{Handle: 30, Exprs: []facts.Expr{
			{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
			{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: addrHex}},
			{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
			{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "20fb"}},
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
		}}
	}
	// publicAddrs enumerates interfaces in order, then addresses in order,
	// so the accepted address is second in one case and first in the other.
	cases := []struct {
		name    string
		addrHex string
		wantVia string
	}{
		{"accepted candidate is enumerated second", "c0000237", "192.0.2.55"},
		{"accepted candidate is enumerated first", "cb00710a", "203.0.113.10"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := hostFacts()
			f.Host.Interfaces[0].Addresses = append(f.Host.Interfaces[0].Addresses,
				facts.Addr{IP: "192.0.2.55", Prefix: 24, Family: "ip", Scope: "global"})
			filter := ufwFilter()
			filter.Chains[0].Rules = append(filter.Chains[0].Rules, acceptOn(c.addrHex))
			f.Ruleset = facts.Ruleset{Tables: []facts.Table{filter}}
			f.Sockets = []facts.Socket{{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 8443, Unit: "svc.service"}}

			vs := Evaluate(f, InternetZone())
			if len(vs) != 1 {
				t.Fatalf("got %d verdicts, want 1: %+v", len(vs), vs)
			}
			if vs[0].Result != "reachable" {
				t.Fatalf("result = %q (%s), want reachable: one public address accepts", vs[0].Result, vs[0].Reason)
			}
			if !strings.Contains(vs[0].Reason, c.wantVia) {
				t.Fatalf("reason = %q, want it to name the winning candidate %s", vs[0].Reason, c.wantVia)
			}
		})
	}
}
