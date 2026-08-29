//go:build linux

package collect

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/google/nftables/binaryutil"
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

// Bytes captured from a live kernel, recorded in docs/decisions/0003:
// recent[0], `iptables -m recent --set --name SSH`, and recent[1],
// `iptables -m recent --update --seconds 30 --hitcount 6 --name SSH`.
const (
	recentSetHex    = "0000000000000000020053534800554c54000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff00000000"
	recentUpdateHex = "1e00000006000000040053534800554c54000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff00000000"
	// recent[2], `iptables -m recent --rcheck --seconds 60 --name OTHER`.
	recentRcheckHex = "3c0000000000000001004f544845520054000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff00000000"
)

func mustDecodeXtUnknown(t *testing.T, h string) *xt.Unknown {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	u := xt.Unknown(b)
	return &u
}

// The two rules ufw limit ssh emits. --set carries no seconds or hitcount;
// --update carries both, and its name field still needs to decode to just
// "SSH": iptables pre-fills the buffer with "DEFAULT\0", and --name SSH only
// overwrites the first 4 bytes, leaving "ULT\0" in place right after the
// name's own NUL terminator (see docs/decisions/0003).
func TestConvertRecentSetAndUpdate(t *testing.T) {
	setInfo := mustDecodeXtUnknown(t, recentSetHex)
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "recent", Rev: 1, Info: setInfo}})
	r := got[0].Xt.Recent
	if !got[0].Xt.Decoded || r == nil || r.Mode != "set" {
		t.Fatalf("set variant decoded as %+v", got[0].Xt)
	}
	if r.Name != "SSH" {
		t.Fatalf("set variant name = %q, want SSH (not the DEFAULT placeholder tail)", r.Name)
	}

	updInfo := mustDecodeXtUnknown(t, recentUpdateHex)
	got = ConvertExprs([]expr.Any{&expr.Match{Name: "recent", Rev: 1, Info: updInfo}})
	r = got[0].Xt.Recent
	if r == nil || r.Mode != "update" || r.Seconds != 30 || r.HitCount != 6 {
		t.Fatalf("update variant = %+v, want mode update, seconds 30, hitcount 6", r)
	}
}

// The third confirmed bit pattern, captured from a --rcheck rule for
// coverage rather than from either half of ufw limit ssh.
func TestConvertRecentRcheck(t *testing.T) {
	info := mustDecodeXtUnknown(t, recentRcheckHex)
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "recent", Rev: 1, Info: info}})
	r := got[0].Xt.Recent
	if !got[0].Xt.Decoded || r == nil || r.Mode != "rcheck" || r.Seconds != 60 || r.Name != "OTHER" {
		t.Fatalf("rcheck variant = %+v, want mode rcheck, seconds 60, name OTHER", r)
	}
}

// --remove's check_set bit value was never captured (docs/decisions/0003
// only confirms 0x01, 0x02 and 0x04); the pattern the other three follow
// would put it at 0x08, but that is an inference, not evidence. A payload
// otherwise shaped like a real capture but carrying that unconfirmed byte
// must stay undecoded rather than assume the pattern holds.
func TestConvertRecentUnconfirmedCheckSetStaysUndecoded(t *testing.T) {
	data, err := hex.DecodeString(recentSetHex)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	data[8] = 0x08
	info := xt.Unknown(data)
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "recent", Rev: 1, Info: &info}})
	if got[0].Xt.Decoded {
		t.Fatalf("check_set 0x08 decoded as %+v, want undecoded: that bit value was never captured", got[0].Xt)
	}
}

// Only revision 1 is covered by the capture; a different revision must not
// be decoded even though the bytes are otherwise identical.
func TestConvertRecentUnknownRevisionStaysUndecoded(t *testing.T) {
	info := mustDecodeXtUnknown(t, recentSetHex)
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "recent", Rev: 2, Info: info}})
	if got[0].Xt.Decoded {
		t.Fatalf("rev 2 decoded as %+v, want undecoded: only rev 1 is covered by the capture", got[0].Xt)
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
// evaluator, so funnelling an unhandled expression into it made
// "tcp dport 1024-2048 accept" (expr.Range, still undecoded per decision
// 0004) resolve as an unconditional accept. expr.Lookup used to stand in
// here too, before it grew a decoder in v0.2 (see TestConvertLookup*
// below); expr.Fib takes its place as a second still-genuinely-unhandled
// type.
func TestConvertUnhandledExpressionIsUnknown(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Range{Register: 1},
		&expr.Fib{Register: 1, ResultOIFNAME: true},
	})
	for i, want := range []string{"*expr.Range", "*expr.Fib"} {
		if got[i].Kind != facts.ExprUnknown {
			t.Fatalf("expr %d kind = %q, want %q", i, got[i].Kind, facts.ExprUnknown)
		}
		if got[i].Note != want {
			t.Fatalf("expr %d note = %q, want the Go type name %q", i, got[i].Note, want)
		}
	}
}

// The named-set form of "tcp dport @zone_public_ports accept"
// (docs/decisions/0004) decodes unconditionally: nothing about a Lookup
// expression's own fields marks it as out of scope, only the set it names
// can (internal/model/match.go, not the collector, makes that judgement).
func TestConvertLookupNamedSet(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: "zone_public_ports"},
	})
	if got[0].Kind != facts.ExprLookup || got[0].Lookup == nil {
		t.Fatalf("lookup = %+v, want a decoded lookup expression", got[0])
	}
	lk := got[0].Lookup
	if lk.SourceRegister != 1 || lk.Set != "zone_public_ports" || lk.SetID != 0 || lk.Invert {
		t.Fatalf("lookup = %+v, want register 1, set zone_public_ports, no ID, not inverted", lk)
	}
}

// The anonymous-set form (the brace-list "ct state { established, related }
// accept", and "tcp dport { 22, 80 } accept") carries a SetID and no usable
// SetName (decision 0004's census), so the collector must preserve the ID
// rather than lose the reference.
func TestConvertLookupAnonymousSet(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Lookup{SourceRegister: 1, SetID: 7},
	})
	lk := got[0].Lookup
	if lk == nil || lk.Set != "" || lk.SetID != 7 {
		t.Fatalf("lookup = %+v, want no set name and SetID 7", lk)
	}
}

// Invert ("tcp dport != @zone_public_ports") must survive decoding, since
// it flips the membership test in internal/model/match.go.
func TestConvertLookupInvert(t *testing.T) {
	got := ConvertExprs([]expr.Any{
		&expr.Lookup{SourceRegister: 1, SetName: "zone_public_ports", Invert: true},
	})
	if got[0].Lookup == nil || !got[0].Lookup.Invert {
		t.Fatalf("lookup = %+v, want Invert true", got[0].Lookup)
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

// RULING 25: libxt_state sets XT_CONNTRACK_STATE_ALIAS (0x2000) alongside
// XT_CONNTRACK_STATE so iptables can print the match back as "-m state".
// It constrains nothing, so "-m state --state RELATED,ESTABLISHED", which
// arrives as conntrack rev 3 with MatchFlags 0x2001, must decode normally.
func TestConvertConntrackStateAliasDecodesNormally(t *testing.T) {
	info := &xt.ConntrackMtinfo3{}
	info.MatchFlags = 0x2001 // XT_CONNTRACK_STATE | XT_CONNTRACK_STATE_ALIAS
	info.StateMask = 0x6     // related, established
	got := ConvertExprs([]expr.Any{&expr.Match{Name: "conntrack", Rev: 3, Info: info}})

	if !got[0].Xt.Decoded {
		t.Fatalf("a -m state match reported as undecoded: %+v", got[0].Xt)
	}
	ct := got[0].Xt.Conntrack
	if ct == nil || !ct.MatchesState {
		t.Fatalf("conntrack = %+v, want the state half decoded", ct)
	}
	if s := strings.Join(ct.States, ","); s != "established,related" {
		t.Fatalf("states = %q, want established,related", s)
	}
}

// The comma-list form of "ct state established,related accept"
// (docs/decisions/0004) compiles to a bare Ct expression loading the state
// key into a destination register, decoded independently of whatever
// Bitwise/Cmp follows it.
func TestConvertCtState(t *testing.T) {
	got := ConvertExprs([]expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE}})
	if got[0].Kind != facts.ExprCt || got[0].Ct == nil {
		t.Fatalf("ct = %+v, want a decoded ct expression", got[0])
	}
	if got[0].Ct.Key != "state" || got[0].Ct.Register != 1 {
		t.Fatalf("ct = %+v, want key state, register 1", got[0].Ct)
	}
}

// Any CtKey other than STATE constrains something whyopen does not model
// (docs/decisions/0004 only exercised STATE), so it must stay unknown
// rather than being wrapped as though it were understood.
func TestConvertCtUnmodelledKeyStaysUnknown(t *testing.T) {
	for _, key := range []expr.CtKey{expr.CtKeyMARK, expr.CtKeySTATUS, expr.CtKeyDIRECTION} {
		got := ConvertExprs([]expr.Any{&expr.Ct{Register: 1, Key: key}})
		if got[0].Kind != facts.ExprUnknown || got[0].Note != "*expr.Ct" {
			t.Fatalf("key %v = %+v, want unknown noting *expr.Ct", key, got[0])
		}
	}
}

// A source-register Ct writes ct metadata ("ct mark set", for instance)
// rather than reading it, a different statement shape whyopen does not
// model even for the state key, which nft does not actually let you set.
// Refusing it defensively keeps the collector from ever treating a write as
// a match.
func TestConvertCtSourceRegisterStaysUnknown(t *testing.T) {
	got := ConvertExprs([]expr.Any{&expr.Ct{Register: 1, Key: expr.CtKeySTATE, SourceRegister: true}})
	if got[0].Kind != facts.ExprUnknown || got[0].Note != "*expr.Ct" {
		t.Fatalf("source-register ct = %+v, want unknown", got[0])
	}
}

// RULING 27: nft's log statement writes a line and falls through. It cannot
// constrain a match or terminate a rule, so poisoning on it is a false
// unknown.
func TestConvertNativeLogIsTransparent(t *testing.T) {
	got := ConvertExprs([]expr.Any{&expr.Log{}})
	if got[0].Kind != facts.ExprOther || got[0].Note != "log" {
		t.Fatalf("log = %+v, want ExprOther with note \"log\"", got[0])
	}
}

// The native comma-list shape end to end: a Ct/Bitwise/Cmp trio built the
// way github.com/google/nftables's own fixtures build one for "ct state
// established,related" (nftables_test.go, integration/nft_test.go: Register
// 1, Len 4, NativeEndian operands, Cmp neq against zero), run through
// ConvertExprs and then Evaluate exactly like
// TestStateShapedRulesResolveThroughEvaluate does for the xt shape. Port 22
// falls through the established/related accept, since a fresh SYN is state
// new, to a plain "tcp dport 22 accept"; port 5432 has no such rule and
// stays behind the chain's drop policy.
func TestNativeCtStateShapedRulesResolveThroughEvaluate(t *testing.T) {
	acceptEstablishedRelated := []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATE},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4,
			Mask: binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:  binaryutil.NativeEndian.PutUint32(0)},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
	acceptPort22 := []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x16}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}

	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Host: facts.Host{Interfaces: []facts.Interface{{Name: "eth0", Index: 2, Up: true,
			Addresses: []facts.Addr{{IP: "203.0.113.10", Prefix: 24, Family: "ip", Scope: "global"}}}}},
		Sockets: []facts.Socket{
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 5432, Unit: "postgres.service"},
		},
		Ruleset: facts.Ruleset{Tables: []facts.Table{{Family: "inet", Name: "filter", Chains: []facts.Chain{{
			Name: "input", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{
				{Handle: 1, Exprs: ConvertExprs(acceptEstablishedRelated)},
				{Handle: 2, Exprs: ConvertExprs(acceptPort22)},
			},
		}}}}},
	}

	want := map[uint16]string{22: "reachable", 5432: "filtered"}
	vs := model.Evaluate(f, model.InternetZone())
	if len(vs) != 2 {
		t.Fatalf("got %d verdicts, want 2: %+v", len(vs), vs)
	}
	for _, v := range vs {
		if v.Result != want[v.Endpoint.Port] {
			t.Fatalf("port %d = %q (%s), want %q", v.Endpoint.Port, v.Result, v.Reason, want[v.Endpoint.Port])
		}
	}
}

// RULING 25 end to end, the shape the reviewer measured: an input chain with
// policy drop whose rules are written with "-m state". Both must resolve, in
// both directions, and neither may come back unknown.
func TestStateShapedRulesResolveThroughEvaluate(t *testing.T) {
	stateMatch := func(mask uint16) expr.Any {
		info := &xt.ConntrackMtinfo3{}
		info.MatchFlags = 0x2001
		info.StateMask = mask
		return &expr.Match{Name: "conntrack", Rev: 3, Info: info}
	}
	accept := &expr.Verdict{Kind: expr.VerdictAccept}

	f := facts.Facts{
		SchemaVersion: facts.SchemaVersion,
		Host: facts.Host{Interfaces: []facts.Interface{{Name: "eth0", Index: 2, Up: true,
			Addresses: []facts.Addr{{IP: "203.0.113.10", Prefix: 24, Family: "ip", Scope: "global"}}}}},
		Sockets: []facts.Socket{
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 22, Unit: "ssh.service"},
			{Family: "ip", Proto: "tcp", BindIP: "0.0.0.0", Port: 5432, Unit: "postgres.service"},
		},
		Ruleset: facts.Ruleset{Tables: []facts.Table{{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
			Rules: []facts.Rule{
				// -m state --state RELATED,ESTABLISHED -j ACCEPT
				{Handle: 1, Exprs: ConvertExprs([]expr.Any{stateMatch(0x6), accept})},
				// -p tcp --dport 22 -m state --state NEW -j ACCEPT
				{Handle: 2, Exprs: ConvertExprs([]expr.Any{
					&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
					&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{0x00, 0x16}},
					stateMatch(0x8), accept,
				})},
			},
		}}}}},
	}

	want := map[uint16]string{22: "reachable", 5432: "filtered"}
	vs := model.Evaluate(f, model.InternetZone())
	if len(vs) != 2 {
		t.Fatalf("got %d verdicts, want 2: %+v", len(vs), vs)
	}
	for _, v := range vs {
		if v.Result != want[v.Endpoint.Port] {
			t.Fatalf("port %d = %q (%s), want %q", v.Endpoint.Port, v.Result, v.Reason, want[v.Endpoint.Port])
		}
	}
}
