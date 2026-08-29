package facts

import (
	"encoding/json"
	"testing"
)

func TestFactsRoundTrip(t *testing.T) {
	in := Facts{
		SchemaVersion: SchemaVersion,
		Host: Host{
			Hostname: "testhost",
			Interfaces: []Interface{{
				Name: "eth0", Index: 2, Up: true,
				Addresses: []Addr{{IP: "203.0.113.10", Prefix: 22, Family: "ip", Scope: "global"}},
			}},
			Sysctls: Sysctls{IPv4Forward: true, BindV6Only: false},
		},
		Sockets: []Socket{{Family: "ip6", Proto: "tcp", BindIP: "::", Port: 8081, Inode: 12345}},
		Ruleset: Ruleset{Tables: []Table{{
			Family: "ip", Name: "nat",
			Chains: []Chain{{
				Name: "PREROUTING", Base: true, Hook: "prerouting", Priority: -100, Policy: "accept",
				Rules: []Rule{{Handle: 20, Exprs: []Expr{
					{Kind: ExprPayload, Payload: &PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
					{Kind: ExprCmp, Cmp: &CmpExpr{Op: "eq", Register: 1, Data: "7f000001"}},
					{Kind: ExprXt, Xt: &XtExpr{Kind: "target", Name: "DNAT", Rev: 2, Decoded: true,
						DNAT: &DNATInfo{MinIP: "172.20.0.2", MaxIP: "172.20.0.2", MinPort: 2222, MaxPort: 2222}}},
				}}},
			}},
		}}},
		Docker: Docker{Containers: []Container{{
			ID: "abc123", Name: "web-1",
			Publishes: []Publish{{HostIP: "127.0.0.1", HostPort: 3000, ContainerIP: "172.27.0.5", ContainerPort: 3000, Proto: "tcp"}},
		}}},
		Warnings: []Warning{{Source: "docker", Message: "socket not readable"}},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Facts
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := out.Ruleset.Tables[0].Chains[0].Rules[0].Exprs[2].Xt.DNAT
	if got.MinIP != "172.20.0.2" || got.MinPort != 2222 {
		t.Fatalf("DNAT info lost in round trip: %+v", got)
	}
	if out.Host.Interfaces[0].Addresses[0].Scope != "global" {
		t.Fatalf("address scope lost: %+v", out.Host.Interfaces[0])
	}
	if out.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %d, want %d", out.SchemaVersion, SchemaVersion)
	}
}

func TestOmitEmptyKeepsExprsNarrow(t *testing.T) {
	e := Expr{Kind: ExprVerdict, Verdict: &VerdictExpr{Kind: "jump", Chain: "DOCKER-USER"}}
	b, _ := json.Marshal(e)
	if s := string(b); s != `{"kind":"verdict","verdict":{"kind":"jump","chain":"DOCKER-USER"}}` {
		t.Fatalf("unexpected encoding: %s", s)
	}
}
