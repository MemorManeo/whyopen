package model

import (
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
	hostHex := map[string]string{"0.0.0.0": "", "203.0.113.10": "cb00710a", "127.0.0.1": "7f000001"}[hostIP]
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
			DNAT: &facts.DNATInfo{MinIP: "172.20.0.2", MaxIP: "172.20.0.2", MinPort: port, MaxPort: port}}},
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
		ID: "c1", Name: "resourcehub-db",
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
	if v.Endpoint.Owner != "resourcehub-db" {
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
		ID: "c1", Name: "resourcehub-db",
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

// With no ruleset at all for a family, the verdict must not silently claim
// the port is closed.
func TestNoGlobalAddressOfThatFamilyIsExplained(t *testing.T) {
	f := hostFacts() // IPv4 only
	f.Ruleset = facts.Ruleset{Tables: []facts.Table{ufwFilter()}}
	f.Sockets = []facts.Socket{{Family: "ip6", Proto: "tcp", BindIP: "::1", Port: 9000}}

	vs := Evaluate(f, InternetZone())
	if len(vs) != 1 || vs[0].Result != "filtered" || vs[0].Reason == "" {
		t.Fatalf("got %+v, want an explained filtered verdict", vs)
	}
}
