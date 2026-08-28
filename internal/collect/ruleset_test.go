//go:build linux

package collect

import (
	"errors"
	"strings"
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

// fakeNFT is a rulesetSource that answers from fixtures and counts calls, so
// a partial failure and the per-family memoization can both be exercised
// without netlink.
type fakeNFT struct {
	tables     []*nftables.Table
	chains     map[nftables.TableFamily][]*nftables.Chain
	chainsErr  map[nftables.TableFamily]error
	rulesErr   map[string]error
	chainCalls int
}

func (f *fakeNFT) ListTables() ([]*nftables.Table, error) { return f.tables, nil }

func (f *fakeNFT) ListChainsOfTableFamily(fam nftables.TableFamily) ([]*nftables.Chain, error) {
	f.chainCalls++
	if err, ok := f.chainsErr[fam]; ok {
		return nil, err
	}
	return f.chains[fam], nil
}

func (f *fakeNFT) GetRules(t *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	if err, ok := f.rulesErr[t.Name+"/"+c.Name]; ok {
		return nil, err
	}
	return []*nftables.Rule{{Handle: 1}}, nil
}

func twoTableFixture() *fakeNFT {
	filter := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "filter"}
	nat := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: "nat"}
	return &fakeNFT{
		tables: []*nftables.Table{filter, nat},
		chains: map[nftables.TableFamily][]*nftables.Chain{
			nftables.TableFamilyIPv4: {
				{Name: "INPUT", Table: filter},
				{Name: "FORWARD", Table: filter},
				{Name: "PREROUTING", Table: nat},
			},
		},
	}
}

func TestReadRulesetCompleteReadIsNotMarkedFailed(t *testing.T) {
	rs, warns, err := readRuleset(twoTableFixture())
	if err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if rs.ReadFailed {
		t.Fatalf("ReadFailed set on a complete read")
	}
	if len(warns) != 0 {
		t.Fatalf("warnings on a complete read: %+v", warns)
	}
	if len(rs.Tables) != 2 || len(rs.Tables[0].Chains) != 2 || len(rs.Tables[1].Chains) != 1 {
		t.Fatalf("unexpected shape: %+v", rs.Tables)
	}
}

// A chain removed by Docker between ListChainsOfTableFamily and GetRules is
// an ordinary live-host race. Skipping it silently left ReadFailed false, so
// Evaluate's short circuit never fired and Traverse drew a confident verdict
// from a ruleset it had only partly seen.
func TestReadRulesetPartialGetRulesFailureMarksIncomplete(t *testing.T) {
	f := twoTableFixture()
	f.rulesErr = map[string]error{"filter/FORWARD": errors.New("no such file or directory")}

	rs, warns, err := readRuleset(f)
	if err != nil {
		t.Fatalf("readRuleset returned a hard error on a partial failure: %v", err)
	}
	if !rs.ReadFailed {
		t.Fatalf("ReadFailed must be set when a chain's rules could not be read")
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "filter/FORWARD") {
		t.Fatalf("warnings = %+v, want one naming the unreadable chain", warns)
	}
	if len(rs.Tables[0].Chains) != 1 {
		t.Fatalf("the readable chain must still be captured: %+v", rs.Tables[0].Chains)
	}
}

// The same for a family whose chains could not be listed at all: the table
// is skipped, so the ruleset is incomplete and must say so.
func TestReadRulesetPartialListChainsFailureMarksIncomplete(t *testing.T) {
	f := twoTableFixture()
	f.chainsErr = map[nftables.TableFamily]error{nftables.TableFamilyIPv4: errors.New("permission denied")}

	rs, _, err := readRuleset(f)
	if err != nil {
		t.Fatalf("readRuleset returned a hard error on a partial failure: %v", err)
	}
	if !rs.ReadFailed {
		t.Fatalf("ReadFailed must be set when a family's chains could not be listed")
	}
	if len(rs.Tables) != 0 {
		t.Fatalf("no table can be captured when its chains are unreadable: %+v", rs.Tables)
	}
}

// ListChainsOfTableFamily returns the whole family, so calling it once per
// table refetches the same list up to five times on a UFW plus Docker host.
func TestReadRulesetListsChainsOncePerFamily(t *testing.T) {
	f := twoTableFixture()
	if _, _, err := readRuleset(f); err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if f.chainCalls != 1 {
		t.Fatalf("ListChainsOfTableFamily called %d times for 2 tables in one family, want 1", f.chainCalls)
	}
}
