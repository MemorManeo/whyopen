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
	// ReadFailed means the ruleset could not be read at all (typically a
	// missing CAP_NET_ADMIN), not that the host genuinely has no rules. A
	// zero-value Ruleset with ReadFailed unset means "read successfully,
	// found nothing" for every document written before this field existed.
	ReadFailed bool `json:"read_failed,omitempty"`
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
	// ExprOther is recorded for completeness and provably never affects a
	// match. Exactly two expressions qualify: counters and limits. Nothing
	// else may be recorded as ExprOther, because the evaluator treats it as
	// fully transparent. Note carries the original kind.
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
	DestTypes   []string `json:"dest_types,omitempty"` // local | unicast | broadcast | ...
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
