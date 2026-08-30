// Package facts is the serializable snapshot of a host that whyopen reasons
// about. It is the only vocabulary shared between collection (privileged,
// host-specific) and evaluation (pure). It imports nothing but the stdlib.
package facts

import (
	"fmt"
	"time"
)

// SchemaVersion is the version of the facts document this build writes.
//
// It is bumped only for a change that a reader needs new code to survive:
// a field removed or renamed, a field whose meaning or units change, or a
// field whose absence starts to mean something different. Adding an
// optional field is not such a change, which is why this has stayed at 1
// through every field added since: an older reader ignores what it does
// not know, and a newer one reads absence as "the collecting build did
// not record this", never as a fact about the host.
//
// The rule that makes a bump safe is that the code to read the older
// document has to exist before the bump lands, not after. See
// SupportedSchema and docs/decisions/0010-facts-schema-versioning.md.
const SchemaVersion = 1

// SupportedSchema reports whether this build can read a document written
// at version v, and says why not when it cannot.
//
// Older is readable, newer is not. A build that refused the documents its
// own predecessors wrote would break the promise the preserved payloads
// exist to keep, that a snapshot can be collected once and evaluated
// later by a better build. A document from a later build is the one case
// where refusing is right: this build cannot know what changed in it, and
// reading it on the assumption that nothing important did is how a tool
// reports a confident wrong answer.
func SupportedSchema(v int) error {
	if v < 1 {
		return fmt.Errorf("no usable schema_version (%d), so this is not a facts document whyopen wrote", v)
	}
	if v > SchemaVersion {
		return fmt.Errorf("facts schema version %d is newer than the %d this build reads; upgrade whyopen", v, SchemaVersion)
	}
	return nil
}

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
	// Forwarding is this interface's own net.ipv4.conf.<name>.forwarding
	// and net.ipv6.conf.<name>.forwarding. Forwarding is a per-device flag
	// and the kernel consults the device the packet arrived on, so a host
	// can leave the global toggle at 0 and still route what comes in here.
	// Reading only the global one reported such a host as filtered, which
	// is the one direction an exposure audit must never be wrong in.
	//
	// Writing the global toggle propagates to every device and to the
	// default for new ones, so the global being on already implies these,
	// and the evaluator takes either as forwarding. That also makes a
	// document from a build that never collected these read exactly as it
	// did before, rather than as a host that suddenly forwards nothing.
	IPv4Forwarding bool `json:"ipv4_forwarding,omitempty"`
	IPv6Forwarding bool `json:"ipv6_forwarding,omitempty"`
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
	// ReadFailed means the ruleset below is not the whole ruleset, not that
	// the host genuinely has no rules. It covers both a total failure
	// (typically a missing CAP_NET_ADMIN) and a partial one: a family whose
	// chains could not be listed, or a chain whose rules could not be read,
	// for instance because Docker removed it mid-read. Either way no
	// confident verdict can be drawn from what was captured. A zero-value
	// Ruleset with ReadFailed unset means "read successfully, found nothing"
	// for every document written before this field existed.
	ReadFailed bool `json:"read_failed,omitempty"`
}

type Table struct {
	Family string  `json:"family"` // ip | ip6 | inet
	Name   string  `json:"name"`
	Chains []Chain `json:"chains"`
	// Sets holds the sets read alongside this table's chains
	// (docs/decisions/0005-reading-set-elements.md), needed to resolve a
	// Lookup expression's set reference. A set whose elements could not be
	// read is omitted here rather than included half-populated: any Lookup
	// naming it then correctly finds nothing and resolves unknown, the same
	// outcome as naming a set that genuinely does not exist.
	Sets []Set `json:"sets,omitempty"`
}

// Set is an nftables named or anonymous set, as read by GetSets and
// GetSetElements. whyopen models only a flat membership test against a set
// of equal-length keys: Interval, IsMap and Concatenation are carried here
// precisely so internal/model/match.go can refuse everything else, an
// interval (range) set, a map or verdict map carrying a value alongside
// each key, or a concatenated key type, rather than guess at what such a
// set would mean to a membership test. See LookupExpr's doc comment for how
// a Lookup expression names one of these.
type Set struct {
	Name      string `json:"name"`
	Anonymous bool   `json:"anonymous"`
	// ID correlates an anonymous set to the Lookup expressions that
	// reference it: decision 0004's census found an anonymous set (the
	// brace-list form of a match, e.g. "ct state { established, related }")
	// is named by ID, not by name, in the Lookup expression that reads it.
	// A named set is still matched by Name first; ID is what makes the
	// anonymous case resolvable at all.
	ID            uint32       `json:"id"`
	Interval      bool         `json:"interval,omitempty"`
	IsMap         bool         `json:"is_map,omitempty"`
	Concatenation bool         `json:"concatenation,omitempty"`
	Elements      []SetElement `json:"elements,omitempty"`
}

// SetElement is one entry of a set. Key, Val and KeyEnd are lowercase hex,
// the same convention CmpExpr.Data already uses, so a facts document stays
// readable by eye. Val is populated only for a map or verdict map element;
// KeyEnd only for an interval element. Both are carried, rather than
// dropped, so the evaluator can refuse either shape as a second line of
// defence even if a set's own Interval or IsMap flag were somehow wrong.
type SetElement struct {
	Key    string `json:"key"`
	Val    string `json:"val,omitempty"`
	KeyEnd string `json:"key_end,omitempty"`
}

type Chain struct {
	Name string `json:"name"`
	Base bool   `json:"base"`
	// Hook is prerouting | input | forward | output | postrouting, empty for
	// regular chains, or "unknown" when the collector met a hook number it
	// could not name. Priority orders base chains within one hook,
	// ascending.
	Hook     string `json:"hook,omitempty"`
	Priority int32  `json:"priority,omitempty"`
	// Devices are the interfaces an ingress or egress base chain is
	// attached to. Those hooks run per device, so this is what says which
	// packets the chain can see, and a chain naming only devices whyopen
	// is not evaluating for cannot affect the verdict. A chain can name
	// several at once (devices = { eth0, eth1 }).
	//
	// Empty means whyopen does not know, not that the chain sees nothing:
	// the evaluator reads it as "could see anything", which is the
	// conservative direction. Reading these at all needs a netlink request
	// the nftables library does not make, recorded in
	// docs/decisions/0006-reading-chain-devices.md.
	Devices []string `json:"devices,omitempty"`
	// Policy is accept | drop for a base chain, empty for a regular chain,
	// or "unknown" when the collector met a policy value it could not name.
	// Both "unknown" and an unexpected empty value make the chain
	// unresolvable to the evaluator rather than defaulting to accept.
	Policy string `json:"policy,omitempty"`
	Rules  []Rule `json:"rules"`
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
	ExprCt      ExprKind = "ct"
	ExprLookup  ExprKind = "lookup"
	ExprVerdict ExprKind = "verdict"
	ExprXt      ExprKind = "xt"
	// ExprOther is recorded for completeness and is treated by the evaluator
	// as fully transparent. Three expressions qualify: counters and logs,
	// which genuinely cannot affect a match, and limits, which can drop
	// traffic above a rate but are deliberately read as transparent anyway,
	// because over-reporting exposure is the safe direction for an audit.
	// Nothing else may be recorded here. Note carries the original kind.
	ExprOther ExprKind = "other"
	// ExprUnknown is an expression whyopen has no decoder for. It is the
	// opposite of transparent: the evaluator must refuse to resolve any
	// rule carrying one, because an unrecognised expression can constrain
	// the match (an anonymous set lookup, a range) or be terminal in its
	// own right. Note carries the original Go type name, for diagnosis.
	ExprUnknown ExprKind = "unknown"
)

type Expr struct {
	Kind    ExprKind     `json:"kind"`
	Payload *PayloadExpr `json:"payload,omitempty"`
	Cmp     *CmpExpr     `json:"cmp,omitempty"`
	Meta    *MetaExpr    `json:"meta,omitempty"`
	Bitwise *BitwiseExpr `json:"bitwise,omitempty"`
	Ct      *CtExpr      `json:"ct,omitempty"`
	Lookup  *LookupExpr  `json:"lookup,omitempty"`
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

// CtExpr is a native `ct` expression: it loads one piece of conntrack
// metainformation into a register for a later Bitwise/Cmp (the comma-list
// form of "ct state", e.g. "ct state established,related accept") or Lookup
// (the brace-list form, e.g. "ct state { established, related } accept",
// not yet decoded) to test. Unlike XtExpr's ConntrackInfo, a native Ct
// expression carries no bytes of its own describing what it constrains: the
// key is everything, so whyopen models only CtKeySTATE, the only key
// docs/decisions/0004-firewalld-expressions.md found a firewalld-shaped
// ruleset actually emit. Any other key stays facts.ExprUnknown rather than
// being wrapped here with nothing to distinguish it.
type CtExpr struct {
	Key      string `json:"key"` // state
	Register uint32 `json:"register"`
}

// LookupExpr is a native `lookup` expression: it tests the current value of
// SourceRegister for membership in the set named by Set (a named set,
// "@myset" in nft syntax) or, when Set is empty, by SetID (an anonymous set
// written inline, e.g. "{ 22, 80 }"). Both are carried because decision
// 0004's census found the kernel names a named set by string and an
// anonymous one by ID, never a name reliable enough to match on; see
// facts.Set's ID field. internal/model/match.go resolves this only as a
// flat membership test against the named facts.Set's elements; see that
// package and facts.Set's doc comments for what is deliberately out of
// scope (an interval set, a map, a concatenated key type, or a set this
// document does not carry at all).
//
// IsDestRegSet is the expression's own statement that this is a map lookup
// writing a value into a destination register, not a plain membership
// test, independently of facts.Set.IsMap: one signal comes from the
// expression, the other from the set it names, and either can be wrong on
// its own (a wrong or missing correlation, a set whose flags were not read
// correctly), so both are checked. The destination register itself is not
// carried: whyopen never resolves a map lookup, so nothing reads it.
type LookupExpr struct {
	SourceRegister uint32 `json:"source_register"`
	Set            string `json:"set,omitempty"`
	SetID          uint32 `json:"set_id,omitempty"`
	Invert         bool   `json:"invert,omitempty"`
	IsDestRegSet   bool   `json:"is_dest_reg_set,omitempty"`
}

// VerdictExpr also carries "reject", which is not an nftables verdict
// expression but a separate terminal statement with no verdict of its own.
// It is recorded here because its effect on reachability is identical to a
// drop, and the evaluator would otherwise have to special-case it twice.
type VerdictExpr struct {
	Kind  string `json:"kind"` // accept | drop | reject | return | jump | goto | continue | queue
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
	Recent    *RecentInfo    `json:"recent,omitempty"`
	// Raw is the extension's payload exactly as the kernel sent it,
	// lowercase hex. Without it a document records only what the
	// collecting build made of an extension, and a later build with a
	// better decoder can make nothing of an older snapshot: see
	// collect.Redecode, which re-derives every expression that has one.
	//
	// It is carried for every xt extension, including the ones the
	// nftables library types before whyopen sees them. Those arrive
	// through a netlink rule dump whyopen issues itself
	// (docs/decisions/0007-preserving-xt-payloads.md), because the library
	// consumes the bytes, and re-marshalling its parsed struct would
	// record a payload whyopen never received rather than the one it did.
	//
	// It is empty in a document written before v0.6.0, and in one whose
	// payload read failed. Both are handled the same way: without bytes
	// there is nothing to re-derive from, and the collector's answer
	// stands.
	Raw string `json:"raw,omitempty"`
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
	DestTypes    []string `json:"dest_types,omitempty"` // local | unicast | broadcast | ...
	SourceTypes  []string `json:"source_types,omitempty"`
	InvertDest   bool     `json:"invert_dest"`
	InvertSource bool     `json:"invert_source"`
}

// RecentInfo is an xt recent match. Mode is set, update, check, rcheck or
// remove. whyopen's synthetic packet is always the first packet from a source
// it has never seen, which is what makes the modes decidable: set records and
// always matches, the checking modes cannot match an empty list, and remove
// has nothing to remove.
type RecentInfo struct {
	Mode     string `json:"mode"`
	Seconds  uint32 `json:"seconds,omitempty"`
	HitCount uint32 `json:"hit_count,omitempty"`
	Invert   bool   `json:"invert,omitempty"`
	Name     string `json:"name,omitempty"`
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
