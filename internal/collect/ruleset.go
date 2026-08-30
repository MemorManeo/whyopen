//go:build linux

package collect

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/google/nftables"
)

// rulesetSource is the read-only slice of *nftables.Conn that whyopen uses.
// Naming it as an interface keeps the read-only promise structural (no write
// call is reachable from this file) and lets the traversal be tested without
// netlink. GetSets and GetSetElements were added in v0.2
// (docs/decisions/0005-reading-set-elements.md) to decode expr.Lookup; no
// further method may be added without a decision record of its own.
type rulesetSource interface {
	ListTables() ([]*nftables.Table, error)
	ListChainsOfTableFamily(family nftables.TableFamily) ([]*nftables.Chain, error)
	GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error)
	GetSets(t *nftables.Table) ([]*nftables.Set, error)
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
}

// Ruleset reads the full nftables ruleset over netlink. It is strictly
// read-only: only ListTables, ListChainsOfTableFamily and GetRules are used.
// Requires CAP_NET_ADMIN.
func Ruleset() (facts.Ruleset, []facts.Warning, error) {
	c, err := nftables.New()
	if err != nil {
		return facts.Ruleset{ReadFailed: true}, nil, fmt.Errorf("open netlink: %w", err)
	}
	return readRuleset(c)
}

// readRuleset walks a source and reports what it managed to read. Any
// failure, total or partial, sets ReadFailed: a ruleset missing one chain is
// not a ruleset whyopen can draw a confident conclusion from, and Evaluate's
// short circuit is the only thing standing between a silently truncated read
// and a confident "reachable". A chain removed by Docker between the list
// call and the GetRules call is an ordinary live-host race, not an exotic
// failure.
func readRuleset(c rulesetSource) (facts.Ruleset, []facts.Warning, error) {
	var warns []facts.Warning

	tables, err := c.ListTables()
	if err != nil {
		return facts.Ruleset{ReadFailed: true}, warns, fmt.Errorf("list tables: %w", err)
	}

	// ListChainsOfTableFamily returns every chain of the family, not of one
	// table, so it is fetched once per family. A UFW plus Docker host has
	// five tables in ip alone.
	type familyChains struct {
		chains []*nftables.Chain
		err    error
	}
	cache := map[nftables.TableFamily]familyChains{}
	listChains := func(f nftables.TableFamily) ([]*nftables.Chain, error) {
		if got, ok := cache[f]; ok {
			return got.chains, got.err
		}
		chains, err := c.ListChainsOfTableFamily(f)
		cache[f] = familyChains{chains: chains, err: err}
		return chains, err
	}

	var rs facts.Ruleset
	for _, t := range tables {
		fam := FamilyName(t.Family)
		// netdev is here for the ingress hook, which runs before
		// prerouting and can drop a packet before any rule the evaluator
		// walks. It was skipped as a family that cannot carry inbound IP
		// verdicts, which is exactly backwards: an ingress chain decides
		// whether the packet exists at all for everything downstream.
		// arp and bridge stay out, neither can decide whether an inbound
		// IP packet reaches a socket on this host.
		if fam != "ip" && fam != "ip6" && fam != "inet" && fam != "netdev" {
			continue
		}
		ft := facts.Table{Family: fam, Name: t.Name}

		sets, setWarns, setsFailed := readSets(c, t, fam)
		warns = append(warns, setWarns...)
		if setsFailed {
			rs.ReadFailed = true
		}
		ft.Sets = sets

		chains, err := listChains(t.Family)
		if err != nil {
			warns = append(warns, facts.Warning{
				Source:  "ruleset",
				Message: fmt.Sprintf("list chains for %s/%s: %v", fam, t.Name, err),
			})
			rs.ReadFailed = true
			continue
		}
		for _, ch := range chains {
			if ch.Table.Name != t.Name || ch.Table.Family != t.Family {
				continue
			}
			fc := facts.Chain{
				Name:   ch.Name,
				Base:   ch.Hooknum != nil,
				Hook:   HookName(ch.Hooknum, t.Family),
				Device: ch.Device,
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
				rs.ReadFailed = true
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

// readSets reads one table's sets and each set's elements, following the
// same degradation posture as chains and rules above: a failure becomes a
// facts.Warning and the third return reports it (the caller folds that into
// Ruleset.ReadFailed) rather than aborting the whole snapshot. A set whose
// elements fail to read is omitted entirely rather than included without
// them: any Lookup that names it then finds nothing in the document and
// resolves unknown, the same outcome as naming a set that never existed,
// which is the correct conservative answer either way.
func readSets(c rulesetSource, t *nftables.Table, fam string) ([]facts.Set, []facts.Warning, bool) {
	var warns []facts.Warning
	nftSets, err := c.GetSets(t)
	if err != nil {
		warns = append(warns, facts.Warning{
			Source:  "ruleset",
			Message: fmt.Sprintf("list sets for %s/%s: %v", fam, t.Name, err),
		})
		return nil, warns, true
	}

	failed := false
	var out []facts.Set
	for _, s := range nftSets {
		elems, err := c.GetSetElements(s)
		if err != nil {
			warns = append(warns, facts.Warning{
				Source:  "ruleset",
				Message: fmt.Sprintf("get elements for set %s/%s/%s: %v", fam, t.Name, s.Name, err),
			})
			failed = true
			continue
		}
		out = append(out, convertSet(s, elems))
	}
	return out, warns, failed
}

// convertSet maps a netlink set and its elements onto whyopen's serializable
// facts.Set. Interval, IsMap and Concatenation are carried through
// unconditionally, decoded or not resolved is a judgement
// internal/model/match.go makes, not this collector.
func convertSet(s *nftables.Set, elems []nftables.SetElement) facts.Set {
	fs := facts.Set{
		Name:          s.Name,
		Anonymous:     s.Anonymous,
		ID:            s.ID,
		Interval:      s.Interval,
		IsMap:         s.IsMap,
		Concatenation: s.Concatenation,
	}
	for _, e := range elems {
		fe := facts.SetElement{Key: hex.EncodeToString(e.Key)}
		if len(e.Val) > 0 {
			fe.Val = hex.EncodeToString(e.Val)
		}
		if len(e.KeyEnd) > 0 {
			fe.KeyEnd = hex.EncodeToString(e.KeyEnd)
		}
		fs.Elements = append(fs.Elements, fe)
	}
	return fs
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

// nfInetIngress is NF_INET_INGRESS, the inet family's own ingress hook,
// added in kernel 5.10. x/sys does not export it, and its value does not
// collide with the five NF_INET hooks below it.
const nfInetIngress = 5

// HookName returns the empty string for a regular (non-base) chain.
//
// The family is not decoration: hook numbers are per family and they
// overlap. NF_NETDEV_INGRESS and NF_INET_PRE_ROUTING are both 0, and
// NF_NETDEV_EGRESS and NF_INET_LOCAL_IN are both 1, so naming a hook
// without knowing the family called a netdev ingress chain "prerouting".
// The evaluator then skipped it as a table of the wrong family, and a
// chain that can drop every packet arriving on a device was invisible to
// an audit whose whole job is to notice that.
func HookName(h *nftables.ChainHook, family nftables.TableFamily) string {
	if h == nil {
		return ""
	}
	if family == nftables.TableFamilyNetdev {
		switch *h {
		case *nftables.ChainHookIngress:
			return "ingress"
		case *nftables.ChainHookEgress:
			return "egress"
		}
		return "unknown"
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
	case nfInetIngress:
		return "ingress"
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

// legacyTableFiles are the /proc entries the ip_tables and ip6_tables kernel
// modules create once they are loaded. iptables-nft never loads those
// modules, so a non-empty file here is a serviceable signal that the legacy
// backend is in use. It is not evidence that any rule exists in it: the
// file lists tables that have been registered, and registering happens as
// soon as anything touches the legacy binary, so the warning says what this
// shows rather than what it would like to conclude.
var legacyTableFiles = []struct {
	rel     string
	backend string
}{
	{"net/ip_tables_names", "iptables-legacy"},
	{"net/ip6_tables_names", "ip6tables-legacy"},
}

// LegacyBackend reports iptables-legacy rules on the host. whyopen reads only
// the nftables ruleset; on a legacy host ListTables succeeds against an empty
// nft ruleset, so without this check every port would report reachable with
// nothing to say it was the wrong backend that was read. procRoot is "/proc"
// in production.
func LegacyBackend(procRoot string) []facts.Warning {
	var warns []facts.Warning
	for _, f := range legacyTableFiles {
		b, err := os.ReadFile(filepath.Join(procRoot, f.rel))
		if errors.Is(err, fs.ErrNotExist) {
			continue // the module is not loaded, which is the ordinary case
		}
		if err != nil {
			// The file is root-only, so an unprivileged run cannot tell
			// whether legacy rules exist. Saying so beats a silent pass:
			// the whole point of the check is that an unnoticed legacy
			// backend makes every verdict wrong in the dangerous direction.
			warns = append(warns, facts.Warning{
				Source:  "ruleset",
				Message: fmt.Sprintf("could not check /proc/%s for %s rules (%v), so whyopen cannot rule out a legacy ruleset it would not see", f.rel, f.backend, err),
			})
			continue
		}
		tables := strings.Fields(string(b))
		if len(tables) == 0 {
			continue
		}
		warns = append(warns, facts.Warning{
			Source: "ruleset",
			Message: fmt.Sprintf("%s has registered the tables %s (/proc/%s). Registering a table is not the same as filling it, and whyopen cannot tell from /proc which of these carry rules: loading the module is enough to create this entry. whyopen reads only the nftables ruleset, so if they do carry rules EVERY verdict below may be incomplete, and a port reported filtered may in fact be open. Check with %s -S",
				f.backend, strings.Join(tables, ", "), f.rel, f.backend),
		})
	}
	return warns
}
