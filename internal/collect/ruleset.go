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
