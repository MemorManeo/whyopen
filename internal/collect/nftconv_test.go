//go:build linux

package collect

import (
	"net"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
)

// The DNAT values are the real ones captured from a Docker publish of
// 127.0.0.1:2222 to 172.20.0.2:2222 (0x8ae == 2222).
func TestConvertDNATTarget(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Target{Name: "DNAT", Rev: 2, Info: &xt.NatRange2{
			NatRange: xt.NatRange{
				Flags:   0x3,
				MinIP:   net.IPv4(172, 20, 0, 2),
				MaxIP:   net.IPv4(172, 20, 0, 2),
				MinPort: 0x8ae,
				MaxPort: 0x8ae,
			},
		}},
	})
	if len(got) != 1 {
		t.Fatalf("got %d exprs, want 1", len(got))
	}
	x := got[0].Xt
	if x == nil || !x.Decoded || x.Name != "DNAT" || x.Kind != "target" {
		t.Fatalf("bad xt expr: %+v", x)
	}
	if x.DNAT.MinIP != "172.20.0.2" || x.DNAT.MinPort != 2222 || x.DNAT.MaxPort != 2222 {
		t.Fatalf("bad DNAT info: %+v", x.DNAT)
	}
}

// StateMask 0x6 is "related,established": established is 0x2, related 0x4.
// A fresh SYN is new (0x8) and must therefore not be in States.
func TestConvertConntrackRelatedEstablished(t *testing.T) {
	info := &xt.ConntrackMtinfo3{}
	info.MatchFlags = 0x1 // XT_CONNTRACK_STATE
	info.StateMask = 0x6
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "conntrack", Rev: 3, Info: info}})
	ct := got[0].Xt.Conntrack
	if !got[0].Xt.Decoded || ct == nil || !ct.MatchesState || ct.Invert {
		t.Fatalf("bad conntrack expr: %+v", got[0].Xt)
	}
	want := map[string]bool{"established": true, "related": true}
	if len(ct.States) != 2 {
		t.Fatalf("states = %v, want established+related", ct.States)
	}
	for _, s := range ct.States {
		if !want[s] {
			t.Fatalf("unexpected state %q in %v", s, ct.States)
		}
	}
}

// Dest 0x4 is LOCAL, as emitted by ufw-not-local's --dst-type LOCAL.
func TestConvertAddrTypeLocal(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Dest: 0x4}},
	})
	at := got[0].Xt.AddrType
	if !got[0].Xt.Decoded || at == nil || len(at.DestTypes) != 1 || at.DestTypes[0] != "local" {
		t.Fatalf("bad addrtype: %+v", at)
	}
}

// Extensions with no typed decoder must be marked undecoded, never guessed.
func TestConvertUnknownXtIsMarkedUndecoded(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Match{Name: "recent", Rev: 1, Info: &xt.Unknown{}},
		&expr.Target{Name: "LOG", Rev: 0, Info: &xt.Unknown{}},
	})
	for i, want := range []string{"recent", "LOG"} {
		if got[i].Xt.Name != want || got[i].Xt.Decoded {
			t.Fatalf("expr %d = %+v, want undecoded %s", i, got[i].Xt, want)
		}
	}
}

func TestConvertNativeExprs(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte("br-x\x00")},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Counter{},
		&expr.Verdict{Kind: expr.VerdictJump, Chain: "DOCKER-USER"},
	})
	if got[0].Meta.Key != "iifname" {
		t.Fatalf("meta key = %q", got[0].Meta.Key)
	}
	if got[1].Cmp.Op != "neq" || got[1].Cmp.Data != "62722d7800" {
		t.Fatalf("cmp = %+v", got[1].Cmp)
	}
	if got[2].Payload.Base != "network" || got[2].Payload.Offset != 16 {
		t.Fatalf("payload = %+v", got[2].Payload)
	}
	if got[3].Kind != facts.ExprOther || got[3].Note != "counter" {
		t.Fatalf("counter = %+v", got[3])
	}
	if got[4].Verdict.Kind != "jump" || got[4].Verdict.Chain != "DOCKER-USER" {
		t.Fatalf("verdict = %+v", got[4].Verdict)
	}
}
