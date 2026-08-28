//go:build linux

package collect

import (
	"net"
	"strings"
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

// C1: an expression with no case in convertExpr must be marked
// facts.ExprUnknown, not facts.ExprOther. ExprOther is transparent to the
// evaluator, so funnelling an anonymous set lookup into it made
// "tcp dport { 22, 80 } accept" resolve as an unconditional accept.
func TestConvertUnhandledExpressionIsUnknown(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: "__set0"},
		&expr.Range{Register: 1},
	})
	for i, want := range []string{"*expr.Lookup", "*expr.Range"} {
		if got[i].Kind != facts.ExprUnknown {
			t.Fatalf("expr %d kind = %q, want %q", i, got[i].Kind, facts.ExprUnknown)
		}
		if got[i].Note != want {
			t.Fatalf("expr %d note = %q, want the Go type name %q", i, got[i].Note, want)
		}
	}
}

// C1: a native nft reject carries no expr.Verdict, so it used to land in the
// silently dropped set. It is terminal, which makes it the most dangerous
// possible member of that set.
func TestConvertRejectIsATerminalVerdict(t *testing.T) {
	got := ConvertExprs([]expr.Any{&expr.Reject{Type: 0, Code: 3}})
	if got[0].Kind != facts.ExprVerdict || got[0].Verdict == nil {
		t.Fatalf("reject = %+v, want a verdict expression", got[0])
	}
	if got[0].Verdict.Kind != "reject" {
		t.Fatalf("reject verdict kind = %q, want reject", got[0].Verdict.Kind)
	}
}

// I2: rev 1 keeps the inverts in Flags, and rev 1 is what iptables-nft
// emits on the reference host, so match.go's InvertDest handling was dead
// against real data: "! --dst-type LOCAL" was read as "--dst-type LOCAL".
func TestConvertAddrTypeV1Inverts(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Dest: 0x4, Flags: 0x2}},
	})
	at := got[0].Xt.AddrType
	if !got[0].Xt.Decoded || at == nil {
		t.Fatalf("addrtype = %+v, want a decoded payload", got[0].Xt)
	}
	if !at.InvertDest || at.InvertSource {
		t.Fatalf("inverts = dest %v source %v, want dest inverted only", at.InvertDest, at.InvertSource)
	}

	got = ConvertExprs([]expr.Any{
		&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Source: 0x4, Flags: 0x1}},
	})
	if at = got[0].Xt.AddrType; !at.InvertSource || at.InvertDest {
		t.Fatalf("inverts = dest %v source %v, want source inverted only", at.InvertDest, at.InvertSource)
	}
}

// LIMIT_IFACE_IN/OUT scopes the match to an interface, which whyopen's
// address-role model does not represent. Decoding the type names and
// discarding that constraint would resolve the rule on a partial reading.
func TestConvertAddrTypeIfaceLimitIsNotFullyDecoded(t *testing.T) {
	for _, flags := range []xt.AddrTypeFlags{0x4, 0x8} {
		got := ConvertExprs([]expr.Any{
			&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Dest: 0x4, Flags: flags}},
		})
		if got[0].Xt.Decoded {
			t.Fatalf("flags 0x%x reported as decoded, want undecoded: the iface limit is not modelled", flags)
		}
	}
}

// I2: conntrack reported Decoded true while carrying only the state bits.
// A match that also constrains --ctorigdstport was then resolved on state
// alone, silently discarding half the condition.
func TestConvertConntrackWithExtraMatchFlagIsNotFullyDecoded(t *testing.T) {
	info := &xt.ConntrackMtinfo3{}
	info.MatchFlags = 0x1 | 0x10 // XT_CONNTRACK_STATE plus XT_CONNTRACK_ORIGDST
	info.StateMask = 0x8
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "conntrack", Rev: 3, Info: info}})
	if got[0].Xt.Decoded {
		t.Fatalf("conntrack with an unmodelled match flag reported as decoded: %+v", got[0].Xt)
	}
	if ct := got[0].Xt.Conntrack; ct == nil || !ct.MatchesState {
		t.Fatalf("the state half must still be recorded for diagnosis: %+v", got[0].Xt)
	}
}

// I3: both lists used to be built by ranging a map, so their order differed
// between runs over identical input. A facts document is meant to be
// committed as a golden fixture and diffed between cron runs, which makes a
// shuffled slice a spurious diff. Assert exact contents, not set membership.
func TestDecodedListsAreInAFixedOrder(t *testing.T) {
	info := &xt.ConntrackMtinfo3{}
	info.MatchFlags = 0x1
	info.StateMask = 0xF // invalid + established + related + new
	got := ConvertExprs([]expr.Any{
		&expr.Match{Name: "conntrack", Rev: 3, Info: info},
		// every addrtype bit whyopen names, dest and source alike
		&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Dest: 0x3F, Source: 0x3F}},
	})

	wantStates := "invalid,established,related,new"
	if s := strings.Join(got[0].Xt.Conntrack.States, ","); s != wantStates {
		t.Fatalf("states = %q, want %q", s, wantStates)
	}
	wantTypes := "unspec,unicast,local,broadcast,anycast,multicast"
	at := got[1].Xt.AddrType
	if s := strings.Join(at.DestTypes, ","); s != wantTypes {
		t.Fatalf("dest types = %q, want %q", s, wantTypes)
	}
	if s := strings.Join(at.SourceTypes, ","); s != wantTypes {
		t.Fatalf("source types = %q, want %q", s, wantTypes)
	}

	// Repeat: a map-ranging regression shows up as an occasional shuffle,
	// not a consistent one.
	for i := 0; i < 200; i++ {
		again := ConvertExprs([]expr.Any{&expr.Match{Name: "addrtype", Rev: 1, Info: &xt.AddrTypeV1{Dest: 0x3F}}})
		if s := strings.Join(again[0].Xt.AddrType.DestTypes, ","); s != wantTypes {
			t.Fatalf("run %d: dest types = %q, want %q", i, s, wantTypes)
		}
	}
}
