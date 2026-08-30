//go:build linux

package collect

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// The second netlink request whyopen issues itself, under the same fence
// as the first: decision 0007 extends decision 0006 by one message type
// and nothing else. NFT_MSG_GETRULE, request and dump flags only, no
// NFT_MSG_NEW*, no NFT_MSG_DEL*, no NLM_F_CREATE, no NLM_F_REPLACE.
//
// It exists because github.com/google/nftables consumes the xt payload it
// can type. For conntrack, addrtype or DNAT it hands over a parsed struct
// and the NFTA_MATCH_INFO or NFTA_TARGET_INFO bytes are gone, so a facts
// document could not keep them and a later build with a better decoder
// could make nothing of an older snapshot, for exactly the extensions
// whyopen has misread before.
//
// It reads one thing: the extension name, revision and payload of each xt
// expression. Every other property of a rule still comes from the library.

// ruleKey identifies a rule. A handle is unique only within its chain, a
// chain name only within its table, and a table name only within its
// family.
type ruleKey struct {
	Family uint8
	Table  string
	Chain  string
	Handle uint64
}

// xtPayload is one xt expression's payload exactly as the kernel sent it.
type xtPayload struct {
	Name string
	Rev  uint32
	Info []byte
}

// RulePayloads returns the xt payloads of every rule that has any, in the
// order the kernel listed them within each rule.
//
// A failure here is never a failure to read the ruleset: it returns a
// warning and no payloads, and the document is exactly as complete as one
// from before whyopen read them, which is to say lossy for typed
// extensions and no worse.
func RulePayloads() (map[ruleKey][]xtPayload, []facts.Warning) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, []facts.Warning{{Source: "ruleset", Message: fmt.Sprintf(
			"could not open netlink to read xt payloads (%v), so this document cannot be re-evaluated by a later build with a better decoder", err)}}
	}
	defer c.Close()

	msg := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETRULE),
			Flags: netlink.Request | netlink.Dump,
		},
		// nfgenmsg: family, version, res_id. AF_UNSPEC asks for every
		// family in one dump.
		Data: []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, 0},
	}
	msgs, err := c.Execute(msg)
	if err != nil {
		return nil, []facts.Warning{{Source: "ruleset", Message: fmt.Sprintf(
			"could not read xt payloads (%v), so this document cannot be re-evaluated by a later build with a better decoder", err)}}
	}
	return parseRulePayloads(msgs), nil
}

// parseRulePayloads pulls the xt payloads out of a rule dump. A message it
// cannot read is skipped rather than fatal: this refinement never gets to
// break a run that would otherwise work.
func parseRulePayloads(msgs []netlink.Message) map[ruleKey][]xtPayload {
	out := map[ruleKey][]xtPayload{}
	for _, m := range msgs {
		// nfgenmsg: family, version, res_id.
		if len(m.Data) < 4 {
			continue
		}
		key := ruleKey{Family: m.Data[0]}
		var payloads []xtPayload

		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			continue
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_RULE_TABLE:
				key.Table = ad.String()
			case unix.NFTA_RULE_CHAIN:
				key.Chain = ad.String()
			case unix.NFTA_RULE_HANDLE:
				key.Handle = ad.Uint64()
			case unix.NFTA_RULE_EXPRESSIONS:
				ad.Do(func(b []byte) error {
					payloads = expressionPayloads(b)
					return nil
				})
			}
		}
		if ad.Err() != nil || key.Table == "" || key.Chain == "" || len(payloads) == 0 {
			continue
		}
		out[key] = payloads
	}
	return out
}

// expressionPayloads walks a rule's expression list and returns the xt
// ones in order. Everything else is skipped without taking a place in the
// sequence, because the sequence is what correlation depends on.
func expressionPayloads(b []byte) []xtPayload {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil
	}
	ad.ByteOrder = binary.BigEndian
	var out []xtPayload
	for ad.Next() {
		if ad.Type() != unix.NFTA_LIST_ELEM {
			continue
		}
		ad.Do(func(elem []byte) error {
			if p, ok := xtFromExpression(elem); ok {
				out = append(out, p)
			}
			return nil
		})
	}
	if ad.Err() != nil {
		return nil
	}
	return out
}

// xtFromExpression reads one expression and reports whether it was an xt
// match or target, which are the only two carrying a payload the library
// consumes.
func xtFromExpression(b []byte) (xtPayload, bool) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return xtPayload{}, false
	}
	ad.ByteOrder = binary.BigEndian

	var kind string
	var p xtPayload
	var found bool
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_EXPR_NAME:
			kind = ad.String()
		case unix.NFTA_EXPR_DATA:
			if kind != "match" && kind != "target" {
				continue
			}
			ad.Do(func(inner []byte) error {
				p, found = xtInfo(inner)
				return nil
			})
		}
	}
	if ad.Err() != nil {
		return xtPayload{}, false
	}
	return p, found
}

// xtInfo reads the extension name, revision and payload. The match and
// target attribute numbers are identical (1, 2, 3 for name, rev and info),
// so one decoder serves both.
func xtInfo(b []byte) (xtPayload, bool) {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return xtPayload{}, false
	}
	ad.ByteOrder = binary.BigEndian

	var p xtPayload
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_MATCH_NAME: // == NFTA_TARGET_NAME
			p.Name = ad.String()
		case unix.NFTA_MATCH_REV: // == NFTA_TARGET_REV
			p.Rev = ad.Uint32()
		case unix.NFTA_MATCH_INFO: // == NFTA_TARGET_INFO
			p.Info = append([]byte(nil), ad.Bytes()...)
		}
	}
	if ad.Err() != nil || p.Name == "" || len(p.Info) == 0 {
		return xtPayload{}, false
	}
	return p, true
}

// attachXtPayloads gives each xt expression the bytes the kernel sent for
// it, correlating by position among xt expressions.
//
// That correlation is the whole of decision 0007's risk, so it is checked
// rather than assumed. The library drops any expression whose name it
// cannot type, so position in the full expression list means nothing, but
// both match and target are always typed, which makes the k-th xt
// expression here the k-th the kernel sent. If the name or revision at a
// position disagree, that assumption has failed for this rule, and
// attaching the rest would be attaching bytes to the wrong expressions:
// it stops instead.
func attachXtPayloads(exprs []facts.Expr, payloads []xtPayload) {
	k := 0
	for i := range exprs {
		if exprs[i].Kind != facts.ExprXt || exprs[i].Xt == nil {
			continue
		}
		if k >= len(payloads) {
			return
		}
		p := payloads[k]
		k++
		if p.Name != exprs[i].Xt.Name || p.Rev != exprs[i].Xt.Rev {
			return
		}
		// An extension the library could not type already carries these
		// same bytes, put there by the collector.
		if exprs[i].Xt.Raw == "" {
			exprs[i].Xt.Raw = hex.EncodeToString(p.Info)
		}
	}
}
