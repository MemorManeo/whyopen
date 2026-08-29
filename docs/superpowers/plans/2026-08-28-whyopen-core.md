# whyopen Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `whyopen collect` and `whyopen check`, so that on any Linux host running UFW plus Docker the tool prints, per listening socket and per address family, whether the internet can reach it and which nftables rules decide that.

**Architecture:** A privileged `collect` stage snapshots four sources (listening sockets, the nftables ruleset over netlink, Docker publishes, host addressing) into a serializable `Facts` document. A pure `model` stage pushes a synthetic inbound packet through the real netfilter hook order against those facts and returns a verdict plus the ordered rule path that produced it. The two stages share nothing but `Facts`, which makes the evaluator a pure function and therefore table-testable with no privileges, no Docker and no kernel.

**Tech Stack:** Go, `github.com/google/nftables` (netlink, plus its `xt` subpackage for iptables-nft compatibility payloads), stdlib `flag`, stdlib `net/http` over a unix socket for Docker. No CLI framework, no Docker SDK.

**Spec:** `docs/superpowers/specs/2026-08-28-whyopen-design.md`
**Decision record:** `docs/decisions/0001-nftables-ruleset-source.md`

**Scope:** This plan covers spec milestones 2 through 4 (collectors, evaluator, report). Milestone 1 (the ruleset-source spike) is already resolved in decision 0001. Milestones 5 through 7 (policy file and exit codes, probe and reconcile, release packaging) are a second plan, written after this one lands. This plan's deliverable stands alone: a working auditor that prints correct verdicts.

## Global Constraints

- Module path: `github.com/MemorManeo/whyopen`.
- `go.mod` declares `go 1.24`. The dev box has Go 1.22.2; `GOTOOLCHAIN=auto` (the default) fetches the newer toolchain automatically. Never require a root-level toolchain upgrade.
- Direct dependencies are limited to `github.com/google/nftables`. Anything else needs justification in the commit message. No `github.com/docker/docker`, no `cobra`, no `viper`.
- Linux only. Files that touch netlink or `/proc` carry `//go:build linux`.
- **Read-only.** No code path may create, modify or delete an nftables rule, an iptables rule, or any Docker object. The only `nftables.Conn` methods permitted anywhere in the tree are `ListTables`, `ListChainsOfTableFamily` and `GetRules`. A reviewer rejecting a task for introducing a write path is correct to do so.
- Never use the em-dash character in code, comments, docs or commit messages. Use a comma, colon, semicolon or parentheses.
- Every task ends with `gofmt -l .` empty, `go vet ./...` clean and `go test ./...` passing.
- Conventional Commits. Commit at the end of every task. Author is the repo's configured identity (MemorManeo, applied automatically by the `includeIf` rule).
- License Apache-2.0, header not required per-file.
- An expression, extension or offset the evaluator cannot resolve produces the `unknown` verdict. Never a guess, never an optimistic default.

## File Structure

```
go.mod
LICENSE                          Apache-2.0
cmd/whyopen/main.go              subcommand dispatch, flag parsing, exit codes
internal/facts/facts.go          the Facts schema: the only vocabulary shared
                                 between collect and model
internal/collect/nftconv.go      google/nftables expr types -> facts.Expr (pure)
internal/collect/ruleset.go      netlink ruleset -> facts.Ruleset
internal/collect/host.go         interfaces, address classification, sysctls
internal/collect/sockets.go      /proc/net/{tcp,tcp6,udp,udp6} -> facts.Socket
internal/collect/docker.go       Docker publishes over the unix socket
internal/collect/collect.go      orchestration, warning accumulation
internal/model/packet.go         the synthetic packet and the internet zone
internal/model/match.go          register file, expression matching (pure)
internal/model/traverse.go       hook order, chain walking, verdict resolution
internal/model/evaluate.go       Facts -> []Verdict, DNAT and routing decision
internal/report/table.go         human table rendering
testdata/facts/*.json            golden Facts fixtures
testdata/proc/*                  fake /proc trees for the socket collector
```

Boundaries that matter: `internal/model` must never import `github.com/google/nftables` or `internal/collect`. If it does, the purity that makes the evaluator testable is gone. `internal/facts` imports nothing but the stdlib.

---

### Task 1: Facts schema and module scaffold

**Files:**
- Create: `go.mod`, `LICENSE`, `.gitignore`
- Create: `internal/facts/facts.go`
- Test: `internal/facts/facts_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: the entire `facts` package vocabulary. Every later task depends on these exact names: `facts.Facts`, `facts.Host`, `facts.Interface`, `facts.Addr`, `facts.Sysctls`, `facts.Socket`, `facts.Ruleset`, `facts.Table`, `facts.Chain`, `facts.Rule`, `facts.Expr`, `facts.ExprKind`, `facts.PayloadExpr`, `facts.CmpExpr`, `facts.MetaExpr`, `facts.BitwiseExpr`, `facts.VerdictExpr`, `facts.XtExpr`, `facts.DNATInfo`, `facts.ConntrackInfo`, `facts.AddrTypeInfo`, `facts.Docker`, `facts.Container`, `facts.Publish`, `facts.Warning`, `facts.SchemaVersion`.

- [ ] **Step 1: Write the failing test**

`internal/facts/facts_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/facts/ -run TestFacts -v`
Expected: FAIL, the package does not compile because none of these types exist.

- [ ] **Step 3: Write the schema**

`internal/facts/facts.go`:

```go
// Package facts is the serializable snapshot of a host that whyopen reasons
// about. It is the only vocabulary shared between collection (privileged,
// host-specific) and evaluation (pure). It imports nothing but the stdlib.
package facts

import "time"

// SchemaVersion is bumped on any breaking change to these types. Readers
// must refuse a document whose version they do not know.
const SchemaVersion = 1

type Facts struct {
	SchemaVersion int       `json:"schema_version"`
	CapturedAt    time.Time `json:"captured_at"`
	Host          Host      `json:"host"`
	Sockets       []Socket  `json:"sockets"`
	Ruleset       Ruleset   `json:"ruleset"`
	Docker        Docker    `json:"docker"`
	Warnings      []Warning `json:"warnings,omitempty"`
}

// Warning records something collection could not see. A verdict derived from
// incomplete facts must be able to say why.
type Warning struct {
	Source  string `json:"source"`
	Message string `json:"message"`
}

type Host struct {
	Hostname   string      `json:"hostname"`
	Interfaces []Interface `json:"interfaces"`
	Sysctls    Sysctls     `json:"sysctls"`
}

type Interface struct {
	Name      string `json:"name"`
	Index     int    `json:"index"`
	Up        bool   `json:"up"`
	Addresses []Addr `json:"addresses"`
}

// Scope is one of: global, private, loopback, link-local, ula, multicast.
// Only "global" addresses are reachable from the internet zone.
type Addr struct {
	IP     string `json:"ip"`
	Prefix int    `json:"prefix"`
	Family string `json:"family"` // ip | ip6
	Scope  string `json:"scope"`
}

type Sysctls struct {
	IPv4Forward bool `json:"ipv4_forward"`
	IPv6Forward bool `json:"ipv6_forward"`
	// BindV6Only false (the kernel default) means a :: bind also accepts IPv4.
	BindV6Only bool `json:"bind_v6_only"`
}

type Socket struct {
	Family    string `json:"family"` // ip | ip6
	Proto     string `json:"proto"`  // tcp | udp
	BindIP    string `json:"bind_ip"`
	Port      uint16 `json:"port"`
	Inode     uint32 `json:"inode"`
	UID       uint32 `json:"uid"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Container string `json:"container,omitempty"`
}

type Ruleset struct {
	Tables []Table `json:"tables"`
}

type Table struct {
	Family string  `json:"family"` // ip | ip6 | inet
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
}

type Chain struct {
	Name string `json:"name"`
	Base bool   `json:"base"`
	// Hook is prerouting | input | forward | output | postrouting, empty for
	// regular chains. Priority orders base chains within one hook, ascending.
	Hook     string `json:"hook,omitempty"`
	Priority int32  `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"` // accept | drop, base chains only
	Rules    []Rule `json:"rules"`
}

type Rule struct {
	Handle uint64 `json:"handle"`
	Exprs  []Expr `json:"exprs"`
}

type ExprKind string

const (
	ExprPayload ExprKind = "payload"
	ExprCmp     ExprKind = "cmp"
	ExprMeta    ExprKind = "meta"
	ExprBitwise ExprKind = "bitwise"
	ExprVerdict ExprKind = "verdict"
	ExprXt      ExprKind = "xt"
	// ExprOther is recorded for completeness and never affects a match:
	// counters and limits. Note carries the original kind.
	ExprOther ExprKind = "other"
)

type Expr struct {
	Kind    ExprKind     `json:"kind"`
	Payload *PayloadExpr `json:"payload,omitempty"`
	Cmp     *CmpExpr     `json:"cmp,omitempty"`
	Meta    *MetaExpr    `json:"meta,omitempty"`
	Bitwise *BitwiseExpr `json:"bitwise,omitempty"`
	Verdict *VerdictExpr `json:"verdict,omitempty"`
	Xt      *XtExpr      `json:"xt,omitempty"`
	Note    string       `json:"note,omitempty"`
}

type PayloadExpr struct {
	DestRegister uint32 `json:"dest_register"`
	Base         string `json:"base"` // link | network | transport
	Offset       uint32 `json:"offset"`
	Len          uint32 `json:"len"`
}

// Data is lowercase hex, so a Facts document stays readable by eye.
type CmpExpr struct {
	Op       string `json:"op"` // eq | neq | lt | lte | gt | gte
	Register uint32 `json:"register"`
	Data     string `json:"data"`
}

type MetaExpr struct {
	Key      string `json:"key"` // iifname | oifname | l4proto | nfproto | other
	Register uint32 `json:"register"`
}

type BitwiseExpr struct {
	SourceRegister uint32 `json:"source_register"`
	DestRegister   uint32 `json:"dest_register"`
	Len            uint32 `json:"len"`
	Mask           string `json:"mask"`
	Xor            string `json:"xor"`
}

type VerdictExpr struct {
	Kind  string `json:"kind"` // accept | drop | return | jump | goto | continue | queue
	Chain string `json:"chain,omitempty"`
}

// XtExpr is an iptables-nft compatibility expression. Decoded reports whether
// the payload was understood; when false only Name is trustworthy.
type XtExpr struct {
	Kind      string         `json:"kind"` // match | target
	Name      string         `json:"name"`
	Rev       uint32         `json:"rev,omitempty"`
	Decoded   bool           `json:"decoded"`
	DNAT      *DNATInfo      `json:"dnat,omitempty"`
	Conntrack *ConntrackInfo `json:"conntrack,omitempty"`
	AddrType  *AddrTypeInfo  `json:"addrtype,omitempty"`
}

type DNATInfo struct {
	MinIP   string `json:"min_ip"`
	MaxIP   string `json:"max_ip"`
	MinPort uint16 `json:"min_port"`
	MaxPort uint16 `json:"max_port"`
}

// MatchesState reports whether this conntrack match constrains ct state at
// all. If it does not, the match is on something whyopen does not model.
type ConntrackInfo struct {
	MatchesState bool     `json:"matches_state"`
	States       []string `json:"states,omitempty"` // new | established | related | invalid
	Invert       bool     `json:"invert"`
}

type AddrTypeInfo struct {
	DestTypes   []string `json:"dest_types,omitempty"`   // local | unicast | broadcast | ...
	SourceTypes []string `json:"source_types,omitempty"`
	InvertDest  bool     `json:"invert_dest"`
}

type Docker struct {
	Available  bool        `json:"available"`
	Containers []Container `json:"containers,omitempty"`
}

type Container struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Publishes []Publish `json:"publishes,omitempty"`
}

type Publish struct {
	HostIP        string `json:"host_ip"`
	HostPort      uint16 `json:"host_port"`
	ContainerIP   string `json:"container_ip,omitempty"`
	ContainerPort uint16 `json:"container_port"`
	Proto         string `json:"proto"`
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/facts/ -v`
Expected: PASS, both tests.

- [ ] **Step 5: Scaffold the module files**

`go.mod`:

```
module github.com/MemorManeo/whyopen

go 1.24
```

`.gitignore`:

```
/whyopen
/dist/
*.test
facts.json
```

Fetch the Apache-2.0 text into `LICENSE`, then:

Run: `gofmt -l . && go vet ./... && go test ./...`
Expected: no gofmt output, no vet output, tests pass.

- [ ] **Step 6: Commit**

```bash
git add go.mod .gitignore LICENSE internal/facts/
git commit -m "feat(facts): add the Facts snapshot schema

The single vocabulary shared between privileged collection and pure
evaluation. Expressions are stored as a self-describing union rather than
raw netlink bytes so the model never imports google/nftables."
```

---

### Task 2: Convert netlink expressions into facts.Expr

This is the highest-risk pure code in the project and it is fully testable without root, because the test constructs `expr` values directly. Every constant below was verified against a real UFW plus Docker ruleset; see decision 0001.

**Files:**
- Create: `internal/collect/nftconv.go`
- Test: `internal/collect/nftconv_test.go`

**Interfaces:**
- Consumes: `facts` from Task 1.
- Produces: `collect.ConvertExprs(exprs []expr.Any) []facts.Expr`.

- [ ] **Step 1: Write the failing test**

`internal/collect/nftconv_test.go`:

```go
//go:build linux

package collect

import (
	"net"
	"testing"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/MemorManeo/whyopen/internal/facts"
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go get github.com/google/nftables@latest && go test ./internal/collect/ -v`
Expected: FAIL, `undefined: ConvertExprs`.

- [ ] **Step 3: Write the converter**

`internal/collect/nftconv.go`:

```go
//go:build linux

// Package collect snapshots a host into a facts.Facts document. It is the
// only package that talks to netlink, /proc and Docker.
package collect

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/google/nftables/expr"
	"github.com/google/nftables/xt"
	"github.com/MemorManeo/whyopen/internal/facts"
)

// xt conntrack state bits, from xt_conntrack.h and confirmed against a live
// ruleset: "ct state related,established" is StateMask 0x6.
const (
	ctStateInvalid     = 0x1
	ctStateEstablished = 0x2
	ctStateRelated     = 0x4
	ctStateNew         = 0x8
)

// xtConntrackStateFlag is XT_CONNTRACK_STATE in MatchFlags.
const xtConntrackStateFlag = 0x1

// xt addrtype flags, from xt_addrtype.h. Dest 0x4 is LOCAL.
var addrTypeNames = map[uint16]string{
	0x1: "unspec", 0x2: "unicast", 0x4: "local", 0x8: "broadcast",
	0x10: "anycast", 0x20: "multicast",
}

// ConvertExprs maps netlink expressions onto whyopen's serializable union.
// Anything without a typed decoder is preserved by name with Decoded false,
// so the evaluator can refuse to guess about it later.
func ConvertExprs(exprs []expr.Any) []facts.Expr {
	out := make([]facts.Expr, 0, len(exprs))
	for _, e := range exprs {
		out = append(out, convertExpr(e))
	}
	return out
}

func convertExpr(e expr.Any) facts.Expr {
	switch v := e.(type) {
	case *expr.Payload:
		return facts.Expr{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{
			DestRegister: v.DestRegister,
			Base:         payloadBaseName(v.Base),
			Offset:       v.Offset,
			Len:          v.Len,
		}}
	case *expr.Cmp:
		return facts.Expr{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{
			Op:       cmpOpName(v.Op),
			Register: v.Register,
			Data:     hex.EncodeToString(v.Data),
		}}
	case *expr.Meta:
		return facts.Expr{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{
			Key: metaKeyName(v.Key), Register: v.Register,
		}}
	case *expr.Bitwise:
		return facts.Expr{Kind: facts.ExprBitwise, Bitwise: &facts.BitwiseExpr{
			SourceRegister: v.SourceRegister,
			DestRegister:   v.DestRegister,
			Len:            v.Len,
			Mask:           hex.EncodeToString(v.Mask),
			Xor:            hex.EncodeToString(v.Xor),
		}}
	case *expr.Verdict:
		return facts.Expr{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{
			Kind: verdictKindName(v.Kind), Chain: v.Chain,
		}}
	case *expr.Match:
		return facts.Expr{Kind: facts.ExprXt, Xt: convertXt("match", v.Name, v.Rev, v.Info)}
	case *expr.Target:
		return facts.Expr{Kind: facts.ExprXt, Xt: convertXt("target", v.Name, v.Rev, v.Info)}
	case *expr.Counter:
		return facts.Expr{Kind: facts.ExprOther, Note: "counter"}
	case *expr.Limit:
		return facts.Expr{Kind: facts.ExprOther, Note: "limit"}
	default:
		return facts.Expr{Kind: facts.ExprOther, Note: fmt.Sprintf("%T", e)}
	}
}

func convertXt(kind, name string, rev uint32, info xt.InfoAny) *facts.XtExpr {
	x := &facts.XtExpr{Kind: kind, Name: name, Rev: rev}
	switch i := info.(type) {
	case *xt.NatRange2:
		x.Decoded = true
		x.DNAT = natRange(i.NatRange)
	case *xt.NatRange:
		x.Decoded = true
		x.DNAT = natRange(*i)
	case *xt.ConntrackMtinfo3:
		x.Decoded = true
		x.Conntrack = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.ConntrackMtinfo2:
		x.Decoded = true
		x.Conntrack = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.ConntrackMtinfo1:
		x.Decoded = true
		x.Conntrack = conntrack(i.MatchFlags, i.InvertFlags, uint16(i.StateMask))
	case *xt.AddrTypeV1:
		x.Decoded = true
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:   addrTypes(i.Dest),
			SourceTypes: addrTypes(i.Source),
		}
	case *xt.AddrType:
		x.Decoded = true
		x.AddrType = &facts.AddrTypeInfo{
			DestTypes:   addrTypes(i.Dest),
			SourceTypes: addrTypes(i.Source),
			InvertDest:  i.InvertDest,
		}
	}
	return x
}

func natRange(r xt.NatRange) *facts.DNATInfo {
	return &facts.DNATInfo{
		MinIP:   ipString(r.MinIP),
		MaxIP:   ipString(r.MaxIP),
		MinPort: r.MinPort,
		MaxPort: r.MaxPort,
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

func conntrack(matchFlags, invertFlags, stateMask uint16) *facts.ConntrackInfo {
	ct := &facts.ConntrackInfo{
		MatchesState: matchFlags&xtConntrackStateFlag != 0,
		Invert:       invertFlags&xtConntrackStateFlag != 0,
	}
	if !ct.MatchesState {
		return ct
	}
	for bit, name := range map[uint16]string{
		ctStateInvalid: "invalid", ctStateEstablished: "established",
		ctStateRelated: "related", ctStateNew: "new",
	} {
		if stateMask&bit != 0 {
			ct.States = append(ct.States, name)
		}
	}
	return ct
}

func addrTypes(mask uint16) []string {
	var out []string
	for bit, name := range addrTypeNames {
		if mask&bit != 0 {
			out = append(out, name)
		}
	}
	return out
}

func payloadBaseName(b expr.PayloadBase) string {
	switch b {
	case expr.PayloadBaseLLHeader:
		return "link"
	case expr.PayloadBaseNetworkHeader:
		return "network"
	case expr.PayloadBaseTransportHeader:
		return "transport"
	}
	return "unknown"
}

func cmpOpName(op expr.CmpOp) string {
	switch op {
	case expr.CmpOpEq:
		return "eq"
	case expr.CmpOpNeq:
		return "neq"
	case expr.CmpOpLt:
		return "lt"
	case expr.CmpOpLte:
		return "lte"
	case expr.CmpOpGt:
		return "gt"
	case expr.CmpOpGte:
		return "gte"
	}
	return "unknown"
}

func metaKeyName(k expr.MetaKey) string {
	switch k {
	case expr.MetaKeyIIFNAME:
		return "iifname"
	case expr.MetaKeyOIFNAME:
		return "oifname"
	case expr.MetaKeyL4PROTO:
		return "l4proto"
	case expr.MetaKeyNFPROTO:
		return "nfproto"
	}
	return "unknown"
}

func verdictKindName(k expr.VerdictKind) string {
	switch k {
	case expr.VerdictAccept:
		return "accept"
	case expr.VerdictDrop:
		return "drop"
	case expr.VerdictJump:
		return "jump"
	case expr.VerdictGoto:
		return "goto"
	case expr.VerdictReturn:
		return "return"
	case expr.VerdictContinue:
		return "continue"
	case expr.VerdictQueue:
		return "queue"
	}
	return "unknown"
}
```

Note on state name ordering: `ConvertExprs` iterates a map, so `States` order is not stable. The test above compares as a set. If a later task needs deterministic output, sort in the reporter, not here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collect/ -v`
Expected: PASS, all five tests.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/nftconv.go internal/collect/nftconv_test.go go.mod go.sum
git commit -m "feat(collect): convert netlink expressions to the facts union

Typed decoding for the three xt payloads that change a verdict: DNAT
destination, conntrack state mask and addrtype dst-type. Every other
extension is preserved by name with Decoded false so the evaluator can
refuse to guess. Constants verified against a live UFW plus Docker
ruleset, see docs/decisions/0001."
```

---

### Task 3: Ruleset collector

**Files:**
- Create: `internal/collect/ruleset.go`
- Test: `internal/collect/ruleset_test.go`

**Interfaces:**
- Consumes: `ConvertExprs` from Task 2.
- Produces: `collect.Ruleset() (facts.Ruleset, []facts.Warning, error)`, plus the pure helpers `collect.HookName(*nftables.ChainHook) string` and `collect.PolicyName(*nftables.ChainPolicy) string`.

- [ ] **Step 1: Write the failing test**

The netlink call itself needs root and is covered by the Task 6 integration run. What is unit-testable, and what actually goes wrong in practice, is the hook and policy mapping. Priorities and policies below are the real ones from a UFW plus Docker host.

`internal/collect/ruleset_test.go`:

```go
//go:build linux

package collect

import (
	"testing"

	"github.com/google/nftables"
)

func TestHookName(t *testing.T) {
	cases := []struct {
		hook *nftables.ChainHook
		want string
	}{
		{nftables.ChainHookPrerouting, "prerouting"},
		{nftables.ChainHookInput, "input"},
		{nftables.ChainHookForward, "forward"},
		{nftables.ChainHookOutput, "output"},
		{nftables.ChainHookPostrouting, "postrouting"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := HookName(c.hook); got != c.want {
			t.Fatalf("HookName = %q, want %q", got, c.want)
		}
	}
}

func TestPolicyName(t *testing.T) {
	drop := nftables.ChainPolicyDrop
	accept := nftables.ChainPolicyAccept
	if got := PolicyName(&drop); got != "drop" {
		t.Fatalf("drop policy = %q", got)
	}
	if got := PolicyName(&accept); got != "accept" {
		t.Fatalf("accept policy = %q", got)
	}
	if got := PolicyName(nil); got != "" {
		t.Fatalf("nil policy = %q, want empty for a regular chain", got)
	}
}

func TestFamilyName(t *testing.T) {
	if got := FamilyName(nftables.TableFamilyIPv4); got != "ip" {
		t.Fatalf("ipv4 = %q", got)
	}
	if got := FamilyName(nftables.TableFamilyIPv6); got != "ip6" {
		t.Fatalf("ipv6 = %q", got)
	}
	if got := FamilyName(nftables.TableFamilyINet); got != "inet" {
		t.Fatalf("inet = %q", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run 'TestHookName|TestPolicyName|TestFamilyName' -v`
Expected: FAIL, `undefined: HookName`.

- [ ] **Step 3: Write the collector**

`internal/collect/ruleset.go`:

```go
//go:build linux

package collect

import (
	"fmt"

	"github.com/google/nftables"
	"github.com/MemorManeo/whyopen/internal/facts"
)

// Ruleset reads the full nftables ruleset over netlink. It is strictly
// read-only: only ListTables, ListChainsOfTableFamily and GetRules are used.
// Requires CAP_NET_ADMIN.
func Ruleset() (facts.Ruleset, []facts.Warning, error) {
	var warns []facts.Warning

	c, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return facts.Ruleset{}, warns, fmt.Errorf("open netlink: %w", err)
	}
	defer c.CloseLasting()

	tables, err := c.ListTables()
	if err != nil {
		return facts.Ruleset{}, warns, fmt.Errorf("list tables: %w", err)
	}

	var rs facts.Ruleset
	for _, t := range tables {
		fam := FamilyName(t.Family)
		if fam != "ip" && fam != "ip6" && fam != "inet" {
			continue // arp, bridge and netdev cannot carry inbound IP verdicts
		}
		ft := facts.Table{Family: fam, Name: t.Name}

		chains, err := c.ListChainsOfTableFamily(t.Family)
		if err != nil {
			warns = append(warns, facts.Warning{
				Source:  "ruleset",
				Message: fmt.Sprintf("list chains for %s/%s: %v", fam, t.Name, err),
			})
			continue
		}
		for _, ch := range chains {
			if ch.Table.Name != t.Name || ch.Table.Family != t.Family {
				continue
			}
			fc := facts.Chain{
				Name:   ch.Name,
				Base:   ch.Hooknum != nil,
				Hook:   HookName(ch.Hooknum),
				Policy: PolicyName(ch.Policy),
			}
			if ch.Priority != nil {
				fc.Priority = int32(*ch.Priority)
			}
			rules, err := c.GetRules(t, ch)
			if err != nil {
				warns = append(warns, facts.Warning{
					Source:  "ruleset",
					Message: fmt.Sprintf("get rules for %s/%s/%s: %v", fam, t.Name, ch.Name, err),
				})
				continue
			}
			for _, r := range rules {
				fc.Rules = append(fc.Rules, facts.Rule{
					Handle: r.Handle,
					Exprs:  ConvertExprs(r.Exprs),
				})
			}
			ft.Chains = append(ft.Chains, fc)
		}
		rs.Tables = append(rs.Tables, ft)
	}
	return rs, warns, nil
}

func FamilyName(f nftables.TableFamily) string {
	switch f {
	case nftables.TableFamilyIPv4:
		return "ip"
	case nftables.TableFamilyIPv6:
		return "ip6"
	case nftables.TableFamilyINet:
		return "inet"
	case nftables.TableFamilyARP:
		return "arp"
	case nftables.TableFamilyBridge:
		return "bridge"
	case nftables.TableFamilyNetdev:
		return "netdev"
	}
	return fmt.Sprintf("family%d", f)
}

// HookName returns the empty string for a regular (non-base) chain.
func HookName(h *nftables.ChainHook) string {
	if h == nil {
		return ""
	}
	switch *h {
	case *nftables.ChainHookPrerouting:
		return "prerouting"
	case *nftables.ChainHookInput:
		return "input"
	case *nftables.ChainHookForward:
		return "forward"
	case *nftables.ChainHookOutput:
		return "output"
	case *nftables.ChainHookPostrouting:
		return "postrouting"
	}
	return "unknown"
}

// PolicyName returns the empty string for a regular chain, which has none.
func PolicyName(p *nftables.ChainPolicy) string {
	if p == nil {
		return ""
	}
	switch *p {
	case nftables.ChainPolicyDrop:
		return "drop"
	case nftables.ChainPolicyAccept:
		return "accept"
	}
	return "unknown"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collect/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/ruleset.go internal/collect/ruleset_test.go
git commit -m "feat(collect): read the nftables ruleset over netlink

Read-only: ListTables, ListChainsOfTableFamily and GetRules only. Chain
failures degrade to a warning rather than aborting the snapshot, so a
partially readable ruleset still yields facts the model can reason about."
```

---

### Task 4: Host and socket collectors

**Files:**
- Create: `internal/collect/host.go`, `internal/collect/sockets.go`
- Test: `internal/collect/host_test.go`, `internal/collect/sockets_test.go`

**Interfaces:**
- Consumes: `facts` from Task 1.
- Produces: `collect.ClassifyAddr(ip netip.Addr) string`, `collect.Host() (facts.Host, []facts.Warning)`, `collect.ParseProcNet(r io.Reader, family, proto string) ([]facts.Socket, error)`, `collect.Sockets(procRoot string) ([]facts.Socket, []facts.Warning)`.

The `procRoot` parameter is what makes this testable without privileges: tests pass a temp directory, production passes `/proc`.

- [ ] **Step 1: Write the failing test**

`internal/collect/sockets_test.go`:

```go
//go:build linux

package collect

import (
	"strings"
	"testing"
)

// Real /proc/net/tcp shape. Address is hex, little-endian per 4-byte group.
// st 0A is TCP_LISTEN; st 01 (ESTABLISHED) must be skipped.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 21456 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19283 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0BB8 0100007F:C1B2 01 00000000:00000000 00:00000000 00000000  1000        0 33445 1 0000000000000000 20 0 0 10 0
`

// A :: bind, which with bind_v6_only=0 also accepts IPv4.
const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 44556 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCPListenersOnly(t *testing.T) {
	got, err := ParseProcNet(strings.NewReader(procNetTCP), "ip", "tcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2 listeners (the established one must be skipped): %+v", len(got), got)
	}
	if got[0].BindIP != "127.0.0.53" || got[0].Port != 53 {
		t.Fatalf("socket 0 = %s:%d, want 127.0.0.53:53", got[0].BindIP, got[0].Port)
	}
	if got[1].BindIP != "0.0.0.0" || got[1].Port != 22 || got[1].Inode != 19283 {
		t.Fatalf("socket 1 = %+v, want 0.0.0.0:22 inode 19283", got[1])
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	got, err := ParseProcNet(strings.NewReader(procNetTCP6), "ip6", "tcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 1 || got[0].BindIP != "::" || got[0].Port != 8081 {
		t.Fatalf("got %+v, want [::]:8081", got)
	}
}
```

`internal/collect/host_test.go`:

```go
//go:build linux

package collect

import (
	"net/netip"
	"testing"
)

func TestClassifyAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10":     "global",
		"172.17.0.1":        "private",
		"10.0.0.5":          "private",
		"192.168.1.1":       "private",
		"127.0.0.1":         "loopback",
		"::1":               "loopback",
		"2001:db8::10": "global",
		"fe80::1":           "link-local",
		"fd00::1":           "ula",
	}
	for in, want := range cases {
		ip := netip.MustParseAddr(in)
		if got := ClassifyAddr(ip); got != want {
			t.Fatalf("ClassifyAddr(%s) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run 'TestParseProcNet|TestClassifyAddr' -v`
Expected: FAIL, `undefined: ParseProcNet`, `undefined: ClassifyAddr`.

- [ ] **Step 3: Write the socket collector**

`internal/collect/sockets.go`:

```go
//go:build linux

package collect

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// tcpListen is TCP_LISTEN in /proc/net/tcp's st column.
const tcpListen = "0A"

// Sockets reads every listening TCP and UDP endpoint. procRoot is "/proc" in
// production and a fixture directory in tests.
func Sockets(procRoot string) ([]facts.Socket, []facts.Warning) {
	var (
		all   []facts.Socket
		warns []facts.Warning
	)
	for _, src := range []struct{ file, family, proto string }{
		{"net/tcp", "ip", "tcp"},
		{"net/tcp6", "ip6", "tcp"},
		{"net/udp", "ip", "udp"},
		{"net/udp6", "ip6", "udp"},
	} {
		f, err := os.Open(filepath.Join(procRoot, src.file))
		if err != nil {
			warns = append(warns, facts.Warning{
				Source: "sockets", Message: fmt.Sprintf("open %s: %v", src.file, err),
			})
			continue
		}
		socks, err := ParseProcNet(f, src.family, src.proto)
		f.Close()
		if err != nil {
			warns = append(warns, facts.Warning{
				Source: "sockets", Message: fmt.Sprintf("parse %s: %v", src.file, err),
			})
			continue
		}
		all = append(all, socks...)
	}

	owners, ownerWarns := socketOwners(procRoot)
	warns = append(warns, ownerWarns...)
	for i := range all {
		if o, ok := owners[all[i].Inode]; ok {
			all[i].PID = o.pid
			all[i].Process = o.comm
			all[i].Unit = o.unit
			all[i].Container = o.container
		}
	}
	return all, warns
}

// ParseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} table. For TCP only
// sockets in LISTEN are returned; for UDP every unconnected socket is, since
// an unconnected UDP socket is a listener.
func ParseProcNet(r io.Reader, family, proto string) ([]facts.Socket, error) {
	var out []facts.Socket
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, remote, st := fields[1], fields[2], fields[3]

		if proto == "tcp" && st != tcpListen {
			continue
		}
		if proto == "udp" && !strings.HasSuffix(remote, ":0000") {
			continue // connected UDP socket, not a listener
		}

		ip, port, err := parseHexAddr(local)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", local, err)
		}
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		inode, _ := strconv.ParseUint(fields[9], 10, 32)

		out = append(out, facts.Socket{
			Family: family, Proto: proto,
			BindIP: ip.String(), Port: port,
			UID: uint32(uid), Inode: uint32(inode),
		})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "3500007F:0035" or the 32-hex-digit IPv6 form. Each
// 4-byte group is stored in host byte order, so every group is reversed.
func parseHexAddr(s string) (netip.Addr, uint16, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("missing port separator")
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if len(raw)%4 != 0 || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("unexpected address length %d", len(raw))
	}
	for g := 0; g < len(raw); g += 4 {
		raw[g], raw[g+3] = raw[g+3], raw[g]
		raw[g+1], raw[g+2] = raw[g+2], raw[g+1]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad address bytes")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, uint16(port), nil
}

type owner struct {
	pid       int
	comm      string
	unit      string
	container string
}

// socketOwners maps socket inode to the process holding it, by scanning
// /proc/<pid>/fd for "socket:[<inode>]" links. Without root this sees only
// the caller's own processes, which is reported as a warning by the caller.
func socketOwners(procRoot string) (map[uint32]owner, []facts.Warning) {
	out := map[uint32]owner{}
	var warns []facts.Warning

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out, []facts.Warning{{Source: "sockets", Message: fmt.Sprintf("read %s: %v", procRoot, err)}}
	}
	denied := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			denied++
			continue
		}
		var o *owner
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 32)
			if err != nil {
				continue
			}
			if o == nil {
				o = &owner{pid: pid, comm: readTrimmed(filepath.Join(procRoot, e.Name(), "comm"))}
				o.unit, o.container = parseCgroup(readTrimmed(filepath.Join(procRoot, e.Name(), "cgroup")))
			}
			out[uint32(inode)] = *o
		}
	}
	if denied > 0 {
		warns = append(warns, facts.Warning{
			Source:  "sockets",
			Message: fmt.Sprintf("could not read fds of %d processes, run as root to attribute every socket", denied),
		})
	}
	return out, warns
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseCgroup extracts a systemd unit or a Docker container id from the
// cgroup v2 path, for example
// "0::/system.slice/my-app.service" or
// "0::/system.slice/docker-<64 hex>.scope".
func parseCgroup(s string) (unit, container string) {
	for _, line := range strings.Split(s, "\n") {
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			path = line[i+1:]
		}
		for _, seg := range strings.Split(path, "/") {
			switch {
			case strings.HasPrefix(seg, "docker-") && strings.HasSuffix(seg, ".scope"):
				container = strings.TrimSuffix(strings.TrimPrefix(seg, "docker-"), ".scope")
			case strings.HasSuffix(seg, ".service"):
				unit = seg
			}
		}
	}
	return unit, container
}
```

- [ ] **Step 4: Write the host collector**

`internal/collect/host.go`:

```go
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

	ifaces, err := net.Interfaces()
	if err != nil {
		warns = append(warns, facts.Warning{Source: "host", Message: fmt.Sprintf("interfaces: %v", err)})
		return h, warns
	}
	for _, i := range ifaces {
		fi := facts.Interface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0}
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

	h.Sysctls = facts.Sysctls{
		IPv4Forward: readSysctlBool(procRoot, "sys/net/ipv4/ip_forward"),
		IPv6Forward: readSysctlBool(procRoot, "sys/net/ipv6/conf/all/forwarding"),
		BindV6Only:  readSysctlBool(procRoot, "sys/net/ipv6/bindv6only"),
	}
	return h, warns
}

func readSysctlBool(procRoot, rel string) bool {
	return strings.TrimSpace(readTrimmed(filepath.Join(procRoot, rel))) == "1"
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/collect/ -v`
Expected: PASS, including the two new test files.

- [ ] **Step 6: Commit**

```bash
git add internal/collect/host.go internal/collect/host_test.go internal/collect/sockets.go internal/collect/sockets_test.go
git commit -m "feat(collect): snapshot host addressing and listening sockets

Sockets come from /proc/net/{tcp,tcp6,udp,udp6} with an injectable proc
root, so parsing is unit-testable with no privileges. Address scope
classification drives the internet zone: only global unicast can be an
inbound destination."
```

---

### Task 5: Docker collector

**Files:**
- Create: `internal/collect/docker.go`
- Test: `internal/collect/docker_test.go`

**Interfaces:**
- Consumes: `facts` from Task 1.
- Produces: `collect.DockerFromSocket(socketPath string) (facts.Docker, []facts.Warning)`.

A hand-rolled client over the unix socket, roughly 60 lines, avoids pulling the entire moby module in for one GET. That is the justification the Global Constraints require.

- [ ] **Step 1: Write the failing test**

`internal/collect/docker_test.go`:

```go
//go:build linux

package collect

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

const containersJSON = `[
 {"Id":"abc123def456","Names":["/web-1"],
  "Ports":[{"IP":"127.0.0.1","PrivatePort":3000,"PublicPort":3000,"Type":"tcp"},
           {"PrivatePort":9229,"Type":"tcp"}],
  "NetworkSettings":{"Networks":{"app_default":{"IPAddress":"172.27.0.5"}}}}
]`

func TestDockerFromSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(containersJSON))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	got, warns := DockerFromSocket(sock)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %+v", warns)
	}
	if !got.Available || len(got.Containers) != 1 {
		t.Fatalf("got %+v", got)
	}
	c := got.Containers[0]
	if c.Name != "web-1" || c.ID != "abc123def456" {
		t.Fatalf("container = %+v", c)
	}
	// Only the published port counts; the unpublished 9229 must be dropped.
	if len(c.Publishes) != 1 {
		t.Fatalf("publishes = %+v, want only the published port", c.Publishes)
	}
	p := c.Publishes[0]
	if p.HostIP != "127.0.0.1" || p.HostPort != 3000 || p.ContainerIP != "172.27.0.5" || p.ContainerPort != 3000 {
		t.Fatalf("publish = %+v", p)
	}
}

func TestDockerMissingSocketIsAWarningNotAnError(t *testing.T) {
	got, warns := DockerFromSocket(filepath.Join(t.TempDir(), "absent.sock"))
	if got.Available {
		t.Fatalf("expected unavailable")
	}
	if len(warns) == 0 {
		t.Fatalf("expected a warning explaining that publishes are unknown")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run TestDocker -v`
Expected: FAIL, `undefined: DockerFromSocket`.

- [ ] **Step 3: Write the collector**

`internal/collect/docker.go`:

```go
//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// DefaultDockerSocket is where the daemon listens on a stock install.
const DefaultDockerSocket = "/var/run/docker.sock"

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort uint16 `json:"PrivatePort"`
		PublicPort  uint16 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// DockerFromSocket lists running containers and their published ports. An
// unreachable daemon is a warning, never an error: the ruleset still carries
// the DNAT rules, so verdicts remain possible, just less well attributed.
func DockerFromSocket(socketPath string) (facts.Docker, []facts.Warning) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://docker/containers/json")
	if err != nil {
		return facts.Docker{}, []facts.Warning{{
			Source:  "docker",
			Message: fmt.Sprintf("daemon unreachable at %s (%v), container names and publishes are unknown", socketPath, err),
		}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return facts.Docker{}, []facts.Warning{{
			Source:  "docker",
			Message: fmt.Sprintf("daemon returned %s listing containers", resp.Status),
		}}
	}

	var raw []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return facts.Docker{}, []facts.Warning{{
			Source: "docker", Message: fmt.Sprintf("decode container list: %v", err),
		}}
	}

	out := facts.Docker{Available: true}
	for _, c := range raw {
		fc := facts.Container{ID: c.ID, Name: containerName(c.Names)}
		ip := firstNetworkIP(c)
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue // exposed inside the network only, never published
			}
			hostIP := p.IP
			if hostIP == "" {
				hostIP = "0.0.0.0"
			}
			fc.Publishes = append(fc.Publishes, facts.Publish{
				HostIP: hostIP, HostPort: p.PublicPort,
				ContainerIP: ip, ContainerPort: p.PrivatePort,
				Proto: p.Type,
			})
		}
		out.Containers = append(out.Containers, fc)
	}
	return out, nil
}

func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func firstNetworkIP(c dockerContainer) string {
	for _, n := range c.NetworkSettings.Networks {
		if n.IPAddress != "" {
			return n.IPAddress
		}
	}
	return ""
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/collect/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/collect/docker.go internal/collect/docker_test.go
git commit -m "feat(collect): read Docker publishes over the unix socket

A 60-line client over net/http rather than the moby module, which would
be the largest dependency in the tree for one GET. An unreachable daemon
degrades to a warning: the DNAT rules still carry the mapping."
```

---

### Task 6: The collect command

**Files:**
- Create: `internal/collect/collect.go`, `cmd/whyopen/main.go`
- Test: `internal/collect/collect_test.go`

**Interfaces:**
- Consumes: all four collectors.
- Produces: `collect.All(opts Options) (facts.Facts, error)` and the `whyopen collect` subcommand.

- [ ] **Step 1: Write the failing test**

`internal/collect/collect_test.go`:

```go
//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// All must never abort on a partial failure: a snapshot with warnings is
// more useful than no snapshot, and the warnings travel with the verdict.
func TestAllDegradesToWarnings(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	// No net/tcp, no docker socket, and netlink will fail unprivileged.
	got, err := All(Options{ProcRoot: proc, DockerSocket: filepath.Join(t.TempDir(), "absent.sock")})
	if err != nil {
		t.Fatalf("All returned a hard error on a degraded host: %v", err)
	}
	if got.SchemaVersion != facts.SchemaVersion {
		t.Fatalf("schema version = %d", got.SchemaVersion)
	}
	if got.CapturedAt.IsZero() {
		t.Fatalf("captured_at not set")
	}
	var sources []string
	for _, w := range got.Warnings {
		sources = append(sources, w.Source)
	}
	if len(sources) == 0 {
		t.Fatalf("expected warnings from the unreadable sources, got none")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collect/ -run TestAll -v`
Expected: FAIL, `undefined: All`.

- [ ] **Step 3: Write the orchestrator**

`internal/collect/collect.go`:

```go
//go:build linux

package collect

import (
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
)

type Options struct {
	ProcRoot     string // "/proc"
	DockerSocket string // DefaultDockerSocket
}

func (o Options) withDefaults() Options {
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.DockerSocket == "" {
		o.DockerSocket = DefaultDockerSocket
	}
	return o
}

// All snapshots the host. Every sub-collector degrades to a warning rather
// than an error, because a partial snapshot still yields useful verdicts and
// the warnings are carried into the report.
func All(opts Options) (facts.Facts, error) {
	opts = opts.withDefaults()

	f := facts.Facts{SchemaVersion: facts.SchemaVersion, CapturedAt: time.Now().UTC()}

	host, warns := Host(opts.ProcRoot)
	f.Host = host
	f.Warnings = append(f.Warnings, warns...)

	socks, warns := Sockets(opts.ProcRoot)
	f.Sockets = socks
	f.Warnings = append(f.Warnings, warns...)

	rs, warns, err := Ruleset()
	f.Warnings = append(f.Warnings, warns...)
	if err != nil {
		f.Warnings = append(f.Warnings, facts.Warning{
			Source:  "ruleset",
			Message: err.Error() + " (whyopen needs CAP_NET_ADMIN, try running as root)",
		})
	}
	f.Ruleset = rs

	dk, warns := DockerFromSocket(opts.DockerSocket)
	f.Docker = dk
	f.Warnings = append(f.Warnings, warns...)

	return f, nil
}
```

- [ ] **Step 4: Write the CLI entry point**

`cmd/whyopen/main.go`:

```go
// Command whyopen reports which ports on this host are reachable from the
// internet and which nftables rules decide that. It never modifies state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/MemorManeo/whyopen/internal/collect"
)

const usage = `whyopen: what is actually reachable from the internet, and why.

Usage:
  whyopen collect [-o FILE]   snapshot this host into a facts document
  whyopen check   [--facts F] report a verdict per listening socket

whyopen is read-only. It never creates, changes or deletes a rule.
`

// Exit codes, per docs/superpowers/specs/2026-08-28-whyopen-design.md.
const (
	exitOK    = 0
	exitError = 3
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitError)
	}
	switch os.Args[1] {
	case "collect":
		os.Exit(runCollect(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(exitError)
	}
}

func runCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ExitOnError)
	out := fs.String("o", "-", "write the facts document here, or - for stdout")
	fs.Parse(args)

	f, err := collect.All(collect.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect: %v\n", err)
		return exitError
	}

	w := os.Stdout
	if *out != "-" {
		file, err := os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", *out, err)
			return exitError
		}
		defer file.Close()
		w = file
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		return exitError
	}
	return exitOK
}
```

- [ ] **Step 5: Run tests and build**

Run: `go build ./... && go test ./... && gofmt -l . && go vet ./...`
Expected: builds, tests pass, no gofmt or vet output.

- [ ] **Step 6: Capture fixture zero on a real host**

This step needs root and produces the golden fixture the evaluator is built against. On the dev box:

```bash
go build -o whyopen ./cmd/whyopen
sudo ./whyopen collect -o /tmp/whyopen-facts.json
```

Verify the snapshot is complete before trusting it:

```bash
python3 - <<'EOF'
import json
f=json.load(open('/tmp/whyopen-facts.json'))
print('sockets:', len(f['sockets']))
print('tables :', [(t['family'],t['name'],len(t['chains'])) for t in f['ruleset']['tables']])
print('rules  :', sum(len(c['rules']) for t in f['ruleset']['tables'] for c in t['chains']))
print('docker :', f['docker']['available'], len(f['docker'].get('containers',[])))
print('warns  :', f.get('warnings',[]))
dn=[e['xt']['dnat'] for t in f['ruleset']['tables'] for c in t['chains']
    for r in c['rules'] for e in r['exprs']
    if e['kind']=='xt' and e['xt'].get('dnat')]
print('dnat   :', dn)
EOF
```

Expected on the reference host: 5 tables, 276 rules, `docker: True`, and a `dnat` list whose entries carry real container addresses and ports. If `dnat` is empty, the xt decoding regressed and Task 2 is wrong.

**This file must not be committed.** It contains the host's public addresses, container names and full ruleset, and the repository is public. Copy a redacted subset into `testdata/facts/` only when a specific test needs it, with public addresses rewritten to documentation ranges (`203.0.113.0/24`, `2001:db8::/32`).

- [ ] **Step 7: Commit**

```bash
git add internal/collect/collect.go internal/collect/collect_test.go cmd/whyopen/main.go
git commit -m "feat(cli): add whyopen collect

Snapshots the host into a facts document on stdout or a file. Every
sub-collector degrades to a warning rather than an error, so a host with
an unreadable Docker socket or no privileges still produces a document
the model can reason about, with the gaps recorded."
```

---

### Task 7: The synthetic packet and expression matching

`internal/model` must not import `github.com/google/nftables` or `internal/collect`. It is a pure function of `facts`, which is what makes every test below run in microseconds with no privileges.

**Files:**
- Create: `internal/model/packet.go`, `internal/model/match.go`
- Test: `internal/model/match_test.go`

**Interfaces:**
- Consumes: `facts` from Task 1.
- Produces: `model.Packet`, `model.Action`, `model.Outcome` (`OutcomeMatch`, `OutcomeNoMatch`, `OutcomeUnknown`), and `model.MatchRule(pkt *Packet, r facts.Rule) (Outcome, Action)`.

- [ ] **Step 1: Write the failing test**

`internal/model/match_test.go`:

```go
package model

import (
	"net/netip"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

func testPacket() *Packet {
	return &Packet{
		Family: "ip", Proto: "tcp",
		Src:     netip.MustParseAddr("198.51.100.7"),
		Dst:     netip.MustParseAddr("203.0.113.10"),
		SrcPort: 41234, DstPort: 5432,
		InIface: "eth0", CtState: "new", DstIsLocal: true,
	}
}

// "ip daddr 203.0.113.10 tcp dport 5432" must match; the same rule with a
// different port must not.
func TestMatchPayloadAndPort(t *testing.T) {
	rule := facts.Rule{Handle: 1, Exprs: []facts.Expr{
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 16, Len: 4}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "cb00710a"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "1538"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	out, act := MatchRule(testPacket(), rule)
	if out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept", out, act)
	}

	rule.Exprs[3].Cmp.Data = "0050" // port 80
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match on a different port", out)
	}
}

// meta iifname is compared against a NUL-terminated name.
func TestMatchIifnameNeq(t *testing.T) {
	rule := facts.Rule{Handle: 2, Exprs: []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "iifname", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "neq", Register: 1, Data: "62722d7800"}}, // "br-x\0"
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
	}}
	// Packet arrives on eth0, which is not br-x, so the neq matches.
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "drop" {
		t.Fatalf("out=%v act=%+v, want match/drop", out, act)
	}
}

// The single most important negative case in the whole tool: Docker and UFW
// both emit "ct state related,established accept", and a fresh inbound SYN
// is state new, so those rules must not match.
func TestConntrackEstablishedDoesNotMatchNewSYN(t *testing.T) {
	rule := facts.Rule{Handle: 3, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "conntrack", Decoded: true,
			Conntrack: &facts.ConntrackInfo{MatchesState: true, States: []string{"established", "related"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("out=%v, want no match: a new SYN is not established or related", out)
	}

	rule.Exprs[0].Xt.Conntrack.States = []string{"new"}
	if out, act := MatchRule(testPacket(), rule); out != OutcomeMatch || act.Kind != "accept" {
		t.Fatalf("out=%v act=%+v, want match/accept for ct state new", out, act)
	}
}

func TestAddrTypeLocal(t *testing.T) {
	rule := facts.Rule{Handle: 4, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "addrtype", Decoded: true,
			AddrType: &facts.AddrTypeInfo{DestTypes: []string{"local"}}}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeMatch {
		t.Fatalf("want match when the destination is local")
	}
	p := testPacket()
	p.DstIsLocal = false
	if out, _ := MatchRule(p, rule); out != OutcomeNoMatch {
		t.Fatalf("want no match when the destination is not local")
	}
}

// An icmp match can never match a TCP packet, so it is resolvable by name.
func TestICMPMatchNeverMatchesTCP(t *testing.T) {
	rule := facts.Rule{Handle: 5, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "icmp"}},
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}},
	}}
	if out, _ := MatchRule(testPacket(), rule); out != OutcomeNoMatch {
		t.Fatalf("want no match: an icmp match cannot match tcp")
	}
}

// Anything not resolvable must be unknown, never an optimistic guess.
func TestUnresolvableExpressionIsUnknown(t *testing.T) {
	for _, e := range []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "network", Offset: 4, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "gt", Register: 1, Data: "00"}},
	} {
		rule := facts.Rule{Handle: 6, Exprs: []facts.Expr{e,
			{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}}}
		if out, _ := MatchRule(testPacket(), rule); out != OutcomeUnknown {
			t.Fatalf("expr %+v gave %v, want unknown", e, out)
		}
	}
}

// A decoded DNAT target yields the rewrite the traversal will apply.
func TestDNATTargetAction(t *testing.T) {
	rule := facts.Rule{Handle: 7, Exprs: []facts.Expr{
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "DNAT", Decoded: true,
			DNAT: &facts.DNATInfo{MinIP: "172.20.0.2", MaxIP: "172.20.0.2", MinPort: 2222, MaxPort: 2222}}},
	}}
	out, act := MatchRule(testPacket(), rule)
	if out != OutcomeMatch || act.Kind != "dnat" || act.DNAT.MinPort != 2222 {
		t.Fatalf("out=%v act=%+v, want a dnat action", out, act)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -v`
Expected: FAIL, the package does not exist.

- [ ] **Step 3: Write the packet**

`internal/model/packet.go`:

```go
// Package model evaluates whether a packet from a given source zone reaches
// a listener, using only a facts snapshot. It is pure: no netlink, no /proc,
// no Docker, no clock. That is what makes it testable.
package model

import "net/netip"

// Packet is the synthetic probe pushed through the ruleset. CtState is always
// "new": whyopen asks whether a fresh inbound connection can be established,
// which is what makes "ct state related,established accept" correctly fail to
// match.
type Packet struct {
	Family     string // ip | ip6
	Proto      string // tcp | udp
	Src        netip.Addr
	Dst        netip.Addr
	SrcPort    uint16
	DstPort    uint16
	InIface    string
	OutIface   string
	CtState    string
	DstIsLocal bool
}

// Action is what a matching rule does.
type Action struct {
	Kind  string // accept | drop | return | jump | goto | continue | dnat | none
	Chain string
	DNAT  *dnat
}

type dnat struct {
	IP   netip.Addr
	Port uint16
}

type Outcome int

const (
	OutcomeMatch Outcome = iota
	OutcomeNoMatch
	OutcomeUnknown
)

func (o Outcome) String() string {
	switch o {
	case OutcomeMatch:
		return "match"
	case OutcomeNoMatch:
		return "no-match"
	}
	return "unknown"
}
```

- [ ] **Step 4: Write the matcher**

`internal/model/match.go`:

```go
package model

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"slices"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// ifnameLen is IFNAMSIZ: nft loads interface names into a fixed-size buffer.
const ifnameLen = 16

// MatchRule evaluates one rule against the packet. It returns OutcomeUnknown
// the moment it meets anything it cannot resolve, so a verdict is never built
// on a guess.
func MatchRule(pkt *Packet, r facts.Rule) (Outcome, Action) {
	regs := map[uint32][]byte{}
	act := Action{Kind: "none"}

	for _, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprPayload:
			b, ok := payloadBytes(pkt, e.Payload)
			if !ok {
				return OutcomeUnknown, act
			}
			regs[e.Payload.DestRegister] = b

		case facts.ExprMeta:
			b, ok := metaBytes(pkt, e.Meta.Key)
			if !ok {
				return OutcomeUnknown, act
			}
			regs[e.Meta.Register] = b

		case facts.ExprBitwise:
			src, ok := regs[e.Bitwise.SourceRegister]
			mask, err1 := hex.DecodeString(e.Bitwise.Mask)
			xor, err2 := hex.DecodeString(e.Bitwise.Xor)
			if !ok || err1 != nil || err2 != nil || len(mask) != len(xor) || len(src) < len(mask) {
				return OutcomeUnknown, act
			}
			out := make([]byte, len(mask))
			for i := range mask {
				out[i] = (src[i] & mask[i]) ^ xor[i]
			}
			regs[e.Bitwise.DestRegister] = out

		case facts.ExprCmp:
			data, err := hex.DecodeString(e.Cmp.Data)
			if err != nil {
				return OutcomeUnknown, act
			}
			reg, ok := regs[e.Cmp.Register]
			if !ok || len(reg) < len(data) {
				return OutcomeUnknown, act
			}
			equal := bytes.Equal(reg[:len(data)], data)
			switch e.Cmp.Op {
			case "eq":
				if !equal {
					return OutcomeNoMatch, act
				}
			case "neq":
				if equal {
					return OutcomeNoMatch, act
				}
			default:
				// Ordered comparisons are used for ranges, which whyopen
				// does not model yet.
				return OutcomeUnknown, act
			}

		case facts.ExprXt:
			out, a, ok := xtExpr(pkt, e.Xt)
			if !ok {
				return OutcomeUnknown, act
			}
			if out == OutcomeNoMatch {
				return OutcomeNoMatch, act
			}
			if a.Kind != "none" {
				act = a
			}

		case facts.ExprVerdict:
			act = Action{Kind: e.Verdict.Kind, Chain: e.Verdict.Chain}

		case facts.ExprOther:
			// counters and limits do not decide a match. A limit can in
			// principle drop traffic, but only above a rate, so treating it
			// as transparent is the conservative direction for an exposure
			// audit: it reports reachable rather than hiding a hole.
		default:
			return OutcomeUnknown, act
		}
	}
	return OutcomeMatch, act
}

// payloadBytes synthesises the requested header slice. Any offset whyopen
// does not model returns false, which becomes an unknown verdict.
func payloadBytes(pkt *Packet, p *facts.PayloadExpr) ([]byte, bool) {
	switch p.Base {
	case "network":
		if pkt.Family == "ip" {
			switch {
			case p.Offset == 9 && p.Len == 1:
				return []byte{protoNumber(pkt.Proto)}, true
			case p.Offset == 12 && p.Len == 4:
				return addrBytes(pkt.Src, 4)
			case p.Offset == 16 && p.Len == 4:
				return addrBytes(pkt.Dst, 4)
			}
			return nil, false
		}
		switch {
		case p.Offset == 6 && p.Len == 1:
			return []byte{protoNumber(pkt.Proto)}, true
		case p.Offset == 8 && p.Len == 16:
			return addrBytes(pkt.Src, 16)
		case p.Offset == 24 && p.Len == 16:
			return addrBytes(pkt.Dst, 16)
		}
		return nil, false

	case "transport":
		switch {
		case p.Offset == 0 && p.Len == 2:
			return []byte{byte(pkt.SrcPort >> 8), byte(pkt.SrcPort)}, true
		case p.Offset == 2 && p.Len == 2:
			return []byte{byte(pkt.DstPort >> 8), byte(pkt.DstPort)}, true
		}
		return nil, false
	}
	return nil, false
}

func addrBytes(a netip.Addr, want int) ([]byte, bool) {
	b := a.AsSlice()
	if len(b) != want {
		return nil, false
	}
	return b, true
}

func metaBytes(pkt *Packet, key string) ([]byte, bool) {
	switch key {
	case "iifname":
		return ifname(pkt.InIface), true
	case "oifname":
		return ifname(pkt.OutIface), true
	case "l4proto":
		return []byte{protoNumber(pkt.Proto)}, true
	case "nfproto":
		if pkt.Family == "ip" {
			return []byte{2}, true // NFPROTO_IPV4
		}
		return []byte{10}, true // NFPROTO_IPV6
	}
	return nil, false
}

func ifname(s string) []byte {
	b := make([]byte, ifnameLen)
	copy(b, s)
	return b
}

func protoNumber(proto string) byte {
	if proto == "udp" {
		return 17
	}
	return 6
}

// xtExpr resolves an iptables-nft compatibility expression. The third return
// reports whether it could be resolved at all.
func xtExpr(pkt *Packet, x *facts.XtExpr) (Outcome, Action, bool) {
	none := Action{Kind: "none"}

	if x.Kind == "target" {
		switch x.Name {
		case "DNAT":
			if !x.Decoded || x.DNAT == nil {
				return OutcomeUnknown, none, false
			}
			ip, err := netip.ParseAddr(x.DNAT.MinIP)
			if err != nil {
				return OutcomeUnknown, none, false
			}
			return OutcomeMatch, Action{Kind: "dnat", DNAT: &dnat{IP: ip, Port: x.DNAT.MinPort}}, true
		case "REJECT":
			return OutcomeMatch, Action{Kind: "drop"}, true
		case "LOG":
			// Non-terminal: logs and falls through to the next expression.
			return OutcomeMatch, none, true
		case "MASQUERADE":
			// Source NAT in postrouting. It never decides inbound delivery,
			// and whyopen does not score postrouting.
			return OutcomeMatch, Action{Kind: "accept"}, true
		}
		return OutcomeUnknown, none, false
	}

	switch x.Name {
	case "conntrack":
		if !x.Decoded || x.Conntrack == nil || !x.Conntrack.MatchesState {
			return OutcomeUnknown, none, false
		}
		hit := slices.Contains(x.Conntrack.States, pkt.CtState)
		if x.Conntrack.Invert {
			hit = !hit
		}
		if hit {
			return OutcomeMatch, none, true
		}
		return OutcomeNoMatch, none, true

	case "addrtype":
		if !x.Decoded || x.AddrType == nil || len(x.AddrType.DestTypes) == 0 {
			return OutcomeUnknown, none, false
		}
		if !slices.Contains(x.AddrType.DestTypes, "local") {
			return OutcomeUnknown, none, false
		}
		hit := pkt.DstIsLocal
		if x.AddrType.InvertDest {
			hit = !hit
		}
		if hit {
			return OutcomeMatch, none, true
		}
		return OutcomeNoMatch, none, true

	case "icmp", "icmp6":
		// Cannot match a TCP or UDP packet, whatever its payload says.
		return OutcomeNoMatch, none, true
	}
	return OutcomeUnknown, none, false
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/model/ -v`
Expected: PASS, all seven tests.

- [ ] **Step 6: Commit**

```bash
git add internal/model/packet.go internal/model/match.go internal/model/match_test.go
git commit -m "feat(model): match a synthetic inbound packet against rules

The packet is fixed at ct state new, which is what makes Docker's and
UFW's 'related,established accept' rules correctly fail to match a fresh
SYN. Any expression, offset or xt extension that cannot be resolved
returns unknown rather than an optimistic guess."
```

---

### Task 8: Chain traversal

The semantics implemented here are the ones operators get wrong, and they are the reason "UFW says deny" and "the port is open" can both be true at once.

**Files:**
- Create: `internal/model/traverse.go`
- Test: `internal/model/traverse_test.go`

**Interfaces:**
- Consumes: `MatchRule` from Task 7.
- Produces: `model.Hit`, `model.Result`, `model.Traverse(rs facts.Ruleset, family, hook string, pkt *Packet) (Result, []Hit)`.

- [ ] **Step 1: Write the failing test**

`internal/model/traverse_test.go`:

```go
package model

import (
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
)

func acceptRule(handle uint64) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "accept"}}}}
}

func dropRule(handle uint64) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}}}}
}

func jumpRule(handle uint64, chain string) facts.Rule {
	return facts.Rule{Handle: handle, Exprs: []facts.Expr{
		{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "jump", Chain: chain}}}}
}

// In nftables, accept in one base chain does NOT skip the other base chains
// registered on the same hook. A later base chain can still drop. This is the
// single most misunderstood rule in the system and the reason a UFW box can
// look closed while Docker holds a port open.
func TestAcceptInOneBaseChainDoesNotSkipTheNext(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "early", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: -10, Policy: "accept",
			Rules: []facts.Rule{acceptRule(1)},
		}}},
		{Family: "ip", Name: "late", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(2)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" {
		t.Fatalf("result = %q, want drop: the later base chain must still run", res.Kind)
	}
	if len(hits) != 2 {
		t.Fatalf("hits = %d, want both base chains visited: %+v", len(hits), hits)
	}
}

// Drop is terminal immediately: nothing after it runs.
func TestDropIsTerminal(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(1), acceptRule(2)},
		}}},
	}}
	res, hits := Traverse(rs, "ip", "input", testPacket())
	if res.Kind != "drop" || len(hits) != 1 {
		t.Fatalf("result=%q hits=%d, want drop after exactly one hit", res.Kind, len(hits))
	}
}

// A base chain that falls through applies its policy.
func TestBaseChainPolicyApplies(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "drop",
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the drop policy to apply", res.Kind)
	}
}

// A jump that falls off the end of the target chain returns to the caller.
func TestJumpReturnsToCaller(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{
				Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "ufw-user-input"), dropRule(2)},
			},
			{Name: "ufw-user-input", Rules: []facts.Rule{}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the rule after the jump to run", res.Kind)
	}
}

// inet chains apply to both families.
func TestInetTableAppliesToIPv4(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "inet", Name: "filter", Chains: []facts.Chain{{
			Name: "input", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{dropRule(1)},
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "drop" {
		t.Fatalf("result = %q, want the inet chain to apply to an ip packet", res.Kind)
	}
}

// An unresolvable rule poisons the verdict rather than being skipped.
func TestUnknownRulePoisonsTheVerdict(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{{
			Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
			Rules: []facts.Rule{{Handle: 1, Exprs: []facts.Expr{
				{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "match", Name: "recent"}},
				{Kind: facts.ExprVerdict, Verdict: &facts.VerdictExpr{Kind: "drop"}},
			}}},
		}}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "unknown" {
		t.Fatalf("result = %q, want unknown", res.Kind)
	}
}

// A jump loop must terminate rather than hang.
func TestJumpLoopTerminates(t *testing.T) {
	rs := facts.Ruleset{Tables: []facts.Table{
		{Family: "ip", Name: "filter", Chains: []facts.Chain{
			{Name: "INPUT", Base: true, Hook: "input", Priority: 0, Policy: "accept",
				Rules: []facts.Rule{jumpRule(1, "a")}},
			{Name: "a", Rules: []facts.Rule{jumpRule(2, "b")}},
			{Name: "b", Rules: []facts.Rule{jumpRule(3, "a")}},
		}},
	}}
	if res, _ := Traverse(rs, "ip", "input", testPacket()); res.Kind != "unknown" {
		t.Fatalf("result = %q, want unknown rather than a hang", res.Kind)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run 'TestAccept|TestDrop|TestBase|TestJump|TestInet|TestUnknown' -v`
Expected: FAIL, `undefined: Traverse`.

- [ ] **Step 3: Write the traversal**

`internal/model/traverse.go`:

```go
package model

import (
	"sort"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// maxJumpDepth bounds chain recursion. A real ruleset nests a handful deep;
// anything past this is a loop, and a loop is reported as unknown, never as
// a hang.
const maxJumpDepth = 32

// Hit is one rule the packet actually reached, in traversal order.
type Hit struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Hook     string `json:"hook,omitempty"`
	Priority int32  `json:"priority"`
	Handle   uint64 `json:"handle"`
	Action   string `json:"action"`
	Rule     facts.Rule `json:"-"`
}

// Result is the outcome of one hook.
type Result struct {
	Kind   string // accept | drop | unknown
	Reason string
	DNAT   *dnat
}

// Traverse pushes the packet through every base chain registered on one hook,
// in ascending priority order, and returns the resulting verdict with the
// ordered list of rules that produced it.
func Traverse(rs facts.Ruleset, family, hook string, pkt *Packet) (Result, []Hit) {
	type baseChain struct {
		table string
		chain facts.Chain
	}
	var bases []baseChain
	for _, t := range rs.Tables {
		if t.Family != family && t.Family != "inet" {
			continue
		}
		for _, ch := range t.Chains {
			if ch.Base && ch.Hook == hook {
				bases = append(bases, baseChain{table: t.Name, chain: ch})
			}
		}
	}
	// Ascending priority; table and chain name only to keep output stable.
	sort.SliceStable(bases, func(i, j int) bool {
		if bases[i].chain.Priority != bases[j].chain.Priority {
			return bases[i].chain.Priority < bases[j].chain.Priority
		}
		if bases[i].table != bases[j].table {
			return bases[i].table < bases[j].table
		}
		return bases[i].chain.Name < bases[j].chain.Name
	})

	w := &walker{rs: rs, family: family, pkt: pkt}
	for _, b := range bases {
		res := w.walkChain(b.table, b.chain, 0)
		switch res.Kind {
		case "drop", "unknown":
			// Terminal for the whole hook.
			return res, w.hits
		case "accept":
			// Continue to the next base chain: in nftables an accept in one
			// base chain does not skip the others on the same hook.
			if w.dnat != nil {
				// A nat chain matched; carry the rewrite out.
			}
		}
	}
	return Result{Kind: "accept", DNAT: w.dnat}, w.hits
}

type walker struct {
	rs     facts.Ruleset
	family string
	pkt    *Packet
	hits   []Hit
	dnat   *dnat
}

func (w *walker) findChain(table, name string) (facts.Chain, bool) {
	for _, t := range w.rs.Tables {
		if t.Name != table || (t.Family != w.family && t.Family != "inet") {
			continue
		}
		for _, ch := range t.Chains {
			if ch.Name == name {
				return ch, true
			}
		}
	}
	return facts.Chain{}, false
}

// walkChain returns accept, drop, unknown, or none for a chain that fell
// through without a verdict.
func (w *walker) walkChain(table string, ch facts.Chain, depth int) Result {
	if depth > maxJumpDepth {
		return Result{Kind: "unknown", Reason: "chain nesting exceeded " + itoa(maxJumpDepth) + ", the ruleset may contain a jump loop"}
	}

	for _, r := range ch.Rules {
		out, act := MatchRule(w.pkt, r)
		if out == OutcomeNoMatch {
			continue
		}
		w.hits = append(w.hits, Hit{
			Family: w.family, Table: table, Chain: ch.Name, Hook: ch.Hook,
			Priority: ch.Priority, Handle: r.Handle, Action: act.Kind, Rule: r,
		})
		if out == OutcomeUnknown {
			return Result{Kind: "unknown", Reason: "rule " + itoa64(r.Handle) + " in " + table + "/" + ch.Name + " uses an expression whyopen cannot resolve"}
		}

		switch act.Kind {
		case "accept":
			return Result{Kind: "accept"}
		case "drop":
			return Result{Kind: "drop", Reason: "dropped by " + table + "/" + ch.Name + " rule " + itoa64(r.Handle)}
		case "dnat":
			w.dnat = act.DNAT
			return Result{Kind: "accept", DNAT: act.DNAT}
		case "return":
			return Result{Kind: "none"}
		case "jump":
			target, ok := w.findChain(table, act.Chain)
			if !ok {
				return Result{Kind: "unknown", Reason: "jump to unknown chain " + act.Chain}
			}
			sub := w.walkChain(table, target, depth+1)
			if sub.Kind != "none" {
				return sub
			}
			// Fell off the end of the target chain: continue after the jump.
		case "goto":
			target, ok := w.findChain(table, act.Chain)
			if !ok {
				return Result{Kind: "unknown", Reason: "goto unknown chain " + act.Chain}
			}
			sub := w.walkChain(table, target, depth+1)
			if sub.Kind != "none" {
				return sub
			}
			// goto does not return to the caller.
			return Result{Kind: "none"}
		case "continue", "none":
			// Next rule.
		default:
			return Result{Kind: "unknown", Reason: "unhandled verdict " + act.Kind}
		}
	}

	if ch.Base {
		if ch.Policy == "drop" {
			return Result{Kind: "drop", Reason: "fell through to the drop policy of " + table + "/" + ch.Name}
		}
		return Result{Kind: "accept"}
	}
	return Result{Kind: "none"}
}
```

Add the two small helpers at the bottom of the same file:

```go
func itoa(i int) string    { return strconv.Itoa(i) }
func itoa64(i uint64) string { return strconv.FormatUint(i, 10) }
```

and add `"strconv"` to the imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/model/ -v`
Expected: PASS, all traversal tests.

- [ ] **Step 5: Commit**

```bash
git add internal/model/traverse.go internal/model/traverse_test.go
git commit -m "feat(model): walk base chains in real netfilter order

Implements the semantics operators get wrong: base chains on one hook run
in ascending priority and an accept in one does not skip the others, only
drop is immediately terminal, jump returns on fallthrough while goto does
not, and a chain that falls through applies its policy. Jump loops are
bounded and reported as unknown rather than hanging."
```

---

### Task 9: Endpoints, the DNAT pipeline, and verdicts

This task assembles the pipeline: prerouting, the routing decision, then input or forward. It also resolves the two subtleties the spec calls out: a container's listening socket lives in another network namespace and therefore never appears in the host's `/proc/net/tcp` (so Docker publishes are endpoints in their own right), and a `::` bind with `bind_v6_only=0` is one socket with two verdicts.

**Files:**
- Create: `internal/model/evaluate.go`
- Test: `internal/model/evaluate_test.go`

**Interfaces:**
- Consumes: `Traverse` from Task 8.
- Produces: `model.Zone`, `model.InternetZone()`, `model.Endpoint`, `model.Verdict`, `model.Evaluate(f facts.Facts, zone Zone) []Verdict`.

- [ ] **Step 1: Write the failing test**

`internal/model/evaluate_test.go`:

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/model/ -run 'TestPublish|TestHostSocket|TestDualStack|TestNoGlobal' -v`
Expected: FAIL, `undefined: Evaluate`.

- [ ] **Step 3: Write the evaluator**

`internal/model/evaluate.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/model/ -v`
Expected: PASS, all of them. If `TestPublishOnAllInterfacesIsReachableDespiteUFW` fails, the pipeline is wrong in a way that matters more than any other bug in this project: fix it before moving on.

- [ ] **Step 5: Commit**

```bash
git add internal/model/evaluate.go internal/model/evaluate_test.go
git commit -m "feat(model): evaluate endpoints through the full pipeline

Prerouting, then the routing decision, then input or forward. Docker
publishes are first-class endpoints because a container socket lives in
another netns and never shows up in the host's /proc/net/tcp, and a ::
bind with bind_v6_only=0 yields one verdict per family. Covers the
canonical trap: published on 0.0.0.0 and reachable while UFW denies."
```

---

### Task 10: Rule rendering, the table report, and `whyopen check`

**Files:**
- Create: `internal/report/render.go`, `internal/report/table.go`
- Modify: `cmd/whyopen/main.go`
- Test: `internal/report/render_test.go`

**Interfaces:**
- Consumes: `model.Verdict`, `model.Hit`.
- Produces: `report.RenderRule(r facts.Rule) string`, `report.Table(w io.Writer, vs []model.Verdict, warns []facts.Warning)`, `report.Explain(w io.Writer, v model.Verdict)`, and the `whyopen check` subcommand.

- [ ] **Step 1: Write the failing test**

`internal/report/render_test.go`:

```go
package report

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

func TestRenderRule(t *testing.T) {
	r := facts.Rule{Handle: 21, Exprs: []facts.Expr{
		{Kind: facts.ExprMeta, Meta: &facts.MetaExpr{Key: "iifname", Register: 1}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "neq", Register: 1, Data: "62722d6162630000000000000000000000"}},
		{Kind: facts.ExprPayload, Payload: &facts.PayloadExpr{DestRegister: 1, Base: "transport", Offset: 2, Len: 2}},
		{Kind: facts.ExprCmp, Cmp: &facts.CmpExpr{Op: "eq", Register: 1, Data: "1538"}},
		{Kind: facts.ExprXt, Xt: &facts.XtExpr{Kind: "target", Name: "DNAT", Decoded: true,
			DNAT: &facts.DNATInfo{MinIP: "172.20.0.2", MinPort: 5432}}},
	}}
	got := RenderRule(r)
	for _, want := range []string{`iifname != "br-abc"`, "dport 5432", "dnat to 172.20.0.2:5432"} {
		if !strings.Contains(got, want) {
			t.Fatalf("RenderRule = %q, missing %q", got, want)
		}
	}
}

func TestTableGroupsWorstFirst(t *testing.T) {
	var sb strings.Builder
	Table(&sb, []model.Verdict{
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 22, Owner: "ssh.service"}, Family: "ip", Result: "filtered"},
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 5432, Owner: "db"}, Family: "ip", Result: "reachable"},
		{Endpoint: model.Endpoint{Proto: "tcp", Port: 9000, Owner: "x"}, Family: "ip", Result: "unknown"},
	}, nil)
	out := sb.String()
	iReach := strings.Index(out, "5432")
	iUnknown := strings.Index(out, "9000")
	iFiltered := strings.Index(out, "22")
	if !(iReach < iUnknown && iUnknown < iFiltered) {
		t.Fatalf("wrong ordering, want reachable then unknown then filtered:\n%s", out)
	}
}

func TestTableSurfacesWarnings(t *testing.T) {
	var sb strings.Builder
	Table(&sb, nil, []facts.Warning{{Source: "docker", Message: "daemon unreachable"}})
	if !strings.Contains(sb.String(), "daemon unreachable") {
		t.Fatalf("warnings must be visible in the report:\n%s", sb.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -v`
Expected: FAIL, the package does not exist.

- [ ] **Step 3: Write the renderer**

`internal/report/render.go`:

```go
// Package report turns verdicts into something a human reads at 2am.
package report

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// RenderRule reconstructs an nft-like one-liner from the stored expressions.
// It is for human eyes only: whyopen never re-emits a rule.
func RenderRule(r facts.Rule) string {
	var parts []string
	var pending string // what the next cmp is comparing against

	for _, e := range r.Exprs {
		switch e.Kind {
		case facts.ExprMeta:
			pending = e.Meta.Key
		case facts.ExprPayload:
			pending = payloadName(e.Payload)
		case facts.ExprCmp:
			if pending == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s %s %s", pending, opSymbol(e.Cmp.Op), cmpValue(pending, e.Cmp.Data)))
			pending = ""
		case facts.ExprXt:
			parts = append(parts, renderXt(e.Xt))
		case facts.ExprVerdict:
			if e.Verdict.Chain != "" {
				parts = append(parts, e.Verdict.Kind+" "+e.Verdict.Chain)
			} else {
				parts = append(parts, e.Verdict.Kind)
			}
		}
	}
	if len(parts) == 0 {
		return fmt.Sprintf("handle %d (no renderable expressions)", r.Handle)
	}
	return strings.Join(parts, " ")
}

func payloadName(p *facts.PayloadExpr) string {
	switch {
	case p.Base == "network" && p.Offset == 12:
		return "saddr"
	case p.Base == "network" && p.Offset == 16:
		return "daddr"
	case p.Base == "network" && (p.Offset == 9 || p.Offset == 6):
		return "protocol"
	case p.Base == "transport" && p.Offset == 0:
		return "sport"
	case p.Base == "transport" && p.Offset == 2:
		return "dport"
	}
	return fmt.Sprintf("%s@%d,%d", p.Base, p.Offset, p.Len)
}

func opSymbol(op string) string {
	if op == "neq" {
		return "!="
	}
	return ""
}

func cmpValue(field, data string) string {
	b, err := hex.DecodeString(data)
	if err != nil {
		return data
	}
	switch field {
	case "iifname", "oifname":
		return `"` + strings.TrimRight(string(b), "\x00") + `"`
	case "sport", "dport":
		if len(b) == 2 {
			return fmt.Sprintf("%d", binary.BigEndian.Uint16(b))
		}
	case "saddr", "daddr":
		if len(b) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
		}
	case "protocol":
		if len(b) == 1 {
			switch b[0] {
			case 6:
				return "tcp"
			case 17:
				return "udp"
			}
		}
	}
	return "0x" + data
}

func renderXt(x *facts.XtExpr) string {
	switch {
	case x.Name == "DNAT" && x.DNAT != nil:
		return fmt.Sprintf("dnat to %s:%d", x.DNAT.MinIP, x.DNAT.MinPort)
	case x.Name == "conntrack" && x.Conntrack != nil && x.Conntrack.MatchesState:
		return "ct state " + strings.Join(x.Conntrack.States, ",")
	case x.Name == "addrtype" && x.AddrType != nil:
		return "fib daddr type " + strings.Join(x.AddrType.DestTypes, ",")
	}
	if x.Kind == "target" {
		return strings.ToLower(x.Name)
	}
	return "match " + x.Name + " (undecoded)"
}
```

Note: `opSymbol` returns the empty string for `eq`, which renders `daddr  203.0.113.10`. Collapse the double space with a `strings.ReplaceAll(out, "  ", " ")` before returning from `RenderRule`.

- [ ] **Step 4: Write the table**

`internal/report/table.go`:

```go
package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

// order puts the findings that matter first. Nobody scrolls to find the open
// port.
var order = map[string]int{"reachable": 0, "unknown": 1, "filtered": 2}

func Table(w io.Writer, vs []model.Verdict, warns []facts.Warning) {
	sorted := make([]model.Verdict, len(vs))
	copy(sorted, vs)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && order[sorted[j].Result] < order[sorted[j-1].Result]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RESULT\tPORT\tFAMILY\tOWNER\tBIND\tWHY")
	for _, v := range sorted {
		fmt.Fprintf(tw, "%s\t%d/%s\t%s\t%s\t%s\t%s\n",
			v.Result, v.Endpoint.Port, v.Endpoint.Proto, family(v.Family),
			dash(v.Endpoint.Owner), dash(v.Endpoint.BindIP), v.Reason)
	}
	tw.Flush()

	if len(warns) > 0 {
		fmt.Fprintln(w, "\nwarnings (the snapshot is incomplete, verdicts above may be too):")
		for _, x := range warns {
			fmt.Fprintf(w, "  %s: %s\n", x.Source, x.Message)
		}
	}
}

// Explain prints the ordered rule path behind one verdict.
func Explain(w io.Writer, v model.Verdict) {
	fmt.Fprintf(w, "%d/%s over %s is %s\n  %s\n\n",
		v.Endpoint.Port, v.Endpoint.Proto, family(v.Family), v.Result, v.Reason)
	if len(v.Path) == 0 {
		fmt.Fprintln(w, "  no rule was reached")
		return
	}
	for i, h := range v.Path {
		fmt.Fprintf(w, "  %2d. %s %s/%s (hook %s, priority %d, handle %d)\n      %s\n",
			i+1, h.Family, h.Table, h.Chain, h.Hook, h.Priority, h.Handle, RenderRule(h.Rule))
	}
}

func family(f string) string {
	if f == "ip6" {
		return "IPv6"
	}
	return "IPv4"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
```

- [ ] **Step 5: Wire up `whyopen check`**

In `cmd/whyopen/main.go`, add the `check` case to the switch and this function:

```go
func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	factsPath := fs.String("facts", "", "evaluate this facts document instead of collecting one")
	explain := fs.Int("explain", 0, "print the full rule path for this port")
	fs.Parse(args)

	var (
		f   facts.Facts
		err error
	)
	if *factsPath != "" {
		b, readErr := os.ReadFile(*factsPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", *factsPath, readErr)
			return exitError
		}
		if err = json.Unmarshal(b, &f); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", *factsPath, err)
			return exitError
		}
		if f.SchemaVersion != facts.SchemaVersion {
			fmt.Fprintf(os.Stderr, "facts schema version %d, this build understands %d\n",
				f.SchemaVersion, facts.SchemaVersion)
			return exitError
		}
	} else {
		f, err = collect.All(collect.Options{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "collect: %v\n", err)
			return exitError
		}
	}

	verdicts := model.Evaluate(f, model.InternetZone())

	if *explain != 0 {
		for _, v := range verdicts {
			if int(v.Endpoint.Port) == *explain {
				report.Explain(os.Stdout, v)
			}
		}
		return exitOK
	}
	report.Table(os.Stdout, verdicts, f.Warnings)
	return exitOK
}
```

Add `check` to the usage text and the imports (`encoding/json`, the three internal packages).

- [ ] **Step 6: Run tests, then the real thing**

Run: `go test ./... && gofmt -l . && go vet ./...`
Expected: all pass, no output from gofmt or vet.

Then on the dev box:

```bash
go build -o whyopen ./cmd/whyopen
sudo ./whyopen check
sudo ./whyopen check --explain 22
```

Expected on the reference host: every Docker publish shows `filtered` with a reason naming the loopback bind (they are all bound to 127.0.0.1 there), ports 22, 80 and 443 show `reachable`, and `--explain 22` prints an ordered path through `ip/filter/INPUT` and UFW's chains. Sanity check the result against `sudo nft list ruleset` by hand before trusting it. If a verdict looks wrong, capture the facts document and add it as a fixture before fixing the model.

- [ ] **Step 7: Write the README**

The first screenful must be a real annotated verdict table, not a feature list. State plainly: read-only, needs root, Linux with nftables, what `unknown` means, and that a facts document contains host addresses and container names so it should be redacted before being attached to a bug report.

- [ ] **Step 8: Commit**

```bash
git add internal/report/ cmd/whyopen/main.go README.md
git commit -m "feat(cli): add whyopen check with a verdict table and explain

Verdicts are grouped worst first, so an open port is the first thing on
screen. Explain prints the ordered rule path with an nft-like rendering
of each rule that was reached. Collection warnings are printed with the
table, because a verdict from an incomplete snapshot must say so."
```

---

## Self-Review

**Spec coverage.** Section 6.1 collect maps to Tasks 3, 4, 5, 6; each sub-collector named in the spec has a task. Section 6.2 model maps to Tasks 7, 8, 9, including the base chain priority semantics, the ct state fixing, the `fib daddr type local` resolution and `unknown` as a first-class verdict. Section 6.4 report maps to Task 10. Section 11.1's open question is closed by decision 0001 and consumed by Task 2. Section 6.3 (probe) and sections 7, 8 (full CLI surface, policy file) are deliberately deferred to the next plan and named below. Section 10's fixture list is partly covered: fixtures 2, 3, 6, 7 and 9 appear as tests in Tasks 7 and 9; fixtures 1, 4, 5 and 8 need the netns harness and move to the next plan with it.

**Placeholder scan.** No TBDs. Every code step carries the code. Every test step carries the assertions. The two steps that cannot be pre-written (capturing fixture zero in Task 6, checking the live output in Task 10) state the exact commands and the exact expected values for the reference host.

**Type consistency.** `facts.Socket.Container` holds a container id from the cgroup, while `facts.Container.Name` holds the Docker name; `socketOwner` prefers `Unit`, and `endpoints` overwrites a socket endpoint with the publish so the human-readable container name wins. `model.dnat` is unexported and therefore excluded from `Verdict`'s JSON with a `-` tag, which is intentional: the DNAT rewrite is shown through `Reason` and the rule path, and the next plan can export it if the JSON output needs it. `Hit.Rule` is likewise `-` tagged so a verdict does not re-serialise the whole ruleset. `MatchRule`, `Traverse`, `Evaluate`, `RenderRule`, `Table` and `Explain` are used with the same signatures everywhere they appear.

**One known gap, recorded rather than hidden.** `Traverse` returns after the first base chain that yields accept or drop, but nftables continues to later base chains after an accept. Task 8's `TestAcceptInOneBaseChainDoesNotSkipTheNext` is written to fail against that reading, so the implementer must carry accept through the loop and only let drop and unknown return early. Keep that test green; it encodes the semantics the whole tool exists to explain.

---

## Next Plan

`docs/superpowers/plans/YYYY-MM-DD-whyopen-guardrail.md`, to be written after this one lands:

1. `whyopen.yaml` policy file, `whyopen policy init`, and exit codes 0, 1, 2, 3.
2. `--json` output with a stable versioned schema.
3. `whyopen probe` and `--probe-from ssh://host`, plus the reconciliation report for model and reality disagreeing.
4. The network namespace integration harness in CI, which unlocks the remaining spec fixtures: clean UFW host, ufw-docker applied, `DOCKER-USER` deny, and the dead publish with no listener behind it.
5. Release: GoReleaser, static amd64 and arm64 binaries, deb and rpm.
