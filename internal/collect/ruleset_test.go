//go:build linux

package collect

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"
)

func TestHookName(t *testing.T) {
	cases := []struct {
		hook   *nftables.ChainHook
		family nftables.TableFamily
		want   string
	}{
		{nftables.ChainHookPrerouting, nftables.TableFamilyIPv4, "prerouting"},
		{nftables.ChainHookInput, nftables.TableFamilyIPv4, "input"},
		{nftables.ChainHookForward, nftables.TableFamilyIPv4, "forward"},
		{nftables.ChainHookOutput, nftables.TableFamilyIPv4, "output"},
		{nftables.ChainHookPostrouting, nftables.TableFamilyIPv4, "postrouting"},
		{nil, nftables.TableFamilyIPv4, ""},
	}
	for _, c := range cases {
		if got := HookName(c.hook, c.family); got != c.want {
			t.Fatalf("HookName = %q, want %q", got, c.want)
		}
	}
}

// The hook numbers overlap between families: NF_NETDEV_INGRESS and
// NF_INET_PRE_ROUTING are both 0, and NF_NETDEV_EGRESS and NF_INET_LOCAL_IN
// are both 1. Naming a hook without its family called a netdev ingress
// chain "prerouting", and the evaluator then skipped it as a table of the
// wrong family: a chain that can drop every packet arriving on a device
// was invisible, which is the dangerous direction for an exposure audit.
func TestHookNameDependsOnTheFamily(t *testing.T) {
	cases := []struct {
		hook   *nftables.ChainHook
		family nftables.TableFamily
		want   string
	}{
		{nftables.ChainHookIngress, nftables.TableFamilyNetdev, "ingress"},
		{nftables.ChainHookEgress, nftables.TableFamilyNetdev, "egress"},
		// The same numbers in an IP family are the IP hooks.
		{nftables.ChainHookIngress, nftables.TableFamilyIPv4, "prerouting"},
		{nftables.ChainHookEgress, nftables.TableFamilyIPv4, "input"},
		// inet gained its own ingress hook (NF_INET_INGRESS, 5) in 5.10.
		{nftables.ChainHookRef(5), nftables.TableFamilyINet, "ingress"},
	}
	for _, c := range cases {
		if got := HookName(c.hook, c.family); got != c.want {
			t.Errorf("HookName(%d, family %d) = %q, want %q", *c.hook, c.family, got, c.want)
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
// without netlink. sets and setsErr are keyed by table name; elements and
// elementsErr by "table/set".
type fakeNFT struct {
	tables      []*nftables.Table
	chains      map[nftables.TableFamily][]*nftables.Chain
	chainsErr   map[nftables.TableFamily]error
	rulesErr    map[string]error
	chainCalls  int
	sets        map[string][]*nftables.Set
	setsErr     map[string]error
	elements    map[string][]nftables.SetElement
	elementsErr map[string]error
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

func (f *fakeNFT) GetSets(t *nftables.Table) ([]*nftables.Set, error) {
	if err, ok := f.setsErr[t.Name]; ok {
		return nil, err
	}
	return f.sets[t.Name], nil
}

func (f *fakeNFT) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	key := s.Table.Name + "/" + s.Name
	if err, ok := f.elementsErr[key]; ok {
		return nil, err
	}
	return f.elements[key], nil
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
	rs, warns, err := readRuleset(twoTableFixture(), nil, nil)
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

	rs, warns, err := readRuleset(f, nil, nil)
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

	rs, _, err := readRuleset(f, nil, nil)
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
	if _, _, err := readRuleset(f, nil, nil); err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if f.chainCalls != 1 {
		t.Fatalf("ListChainsOfTableFamily called %d times for 2 tables in one family, want 1", f.chainCalls)
	}
}

// A table's sets, and each set's elements, are read alongside its chains
// (docs/decisions/0005) and carried into facts.Table.Sets, so a Lookup
// expression in one of that table's rules has something to resolve against.
func TestReadRulesetCarriesSetsAndElements(t *testing.T) {
	f := twoTableFixture()
	filter := f.tables[0]
	f.sets = map[string][]*nftables.Set{
		"filter": {{Table: filter, Name: "zone_public_ports", ID: 3}},
	}
	f.elements = map[string][]nftables.SetElement{
		"filter/zone_public_ports": {{Key: []byte{0, 22}}, {Key: []byte{0x1f, 0x90}}},
	}

	rs, warns, err := readRuleset(f, nil, nil)
	if err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings on a complete read: %+v", warns)
	}
	if rs.ReadFailed {
		t.Fatalf("ReadFailed set on a complete read")
	}
	sets := rs.Tables[0].Sets
	if len(sets) != 1 || sets[0].Name != "zone_public_ports" || sets[0].ID != 3 {
		t.Fatalf("sets = %+v, want one set named zone_public_ports with ID 3", sets)
	}
	if len(sets[0].Elements) != 2 || sets[0].Elements[0].Key != "0016" || sets[0].Elements[1].Key != "1f90" {
		t.Fatalf("elements = %+v, want hex-encoded 22 and 8080", sets[0].Elements)
	}
}

// A GetSets failure is a facts.Warning and marks the read incomplete, the
// same posture as a ListChainsOfTableFamily failure, but it does not stop
// this table's chains and rules from still being read: a set-list failure
// says nothing about whether the chains underneath can be read too.
func TestReadRulesetSetsFailureMarksIncompleteButChainsStillRead(t *testing.T) {
	f := twoTableFixture()
	f.setsErr = map[string]error{"filter": errors.New("permission denied")}

	rs, warns, err := readRuleset(f, nil, nil)
	if err != nil {
		t.Fatalf("readRuleset returned a hard error on a partial failure: %v", err)
	}
	if !rs.ReadFailed {
		t.Fatalf("ReadFailed must be set when a table's sets could not be listed")
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "filter") {
		t.Fatalf("warnings = %+v, want one naming the table", warns)
	}
	if len(rs.Tables[0].Sets) != 0 {
		t.Fatalf("Sets = %+v, want none when the list call failed", rs.Tables[0].Sets)
	}
	if len(rs.Tables[0].Chains) != 2 {
		t.Fatalf("chains = %+v, still expected to be read despite the sets failure", rs.Tables[0].Chains)
	}
}

// A GetSetElements failure for one set is a facts.Warning and marks the read
// incomplete, but only that set is omitted: a sibling set that read
// successfully is still carried, the same granularity a single unreadable
// chain's rules do not cost the rest of the table.
func TestReadRulesetSetElementsFailureOmitsOnlyThatSet(t *testing.T) {
	f := twoTableFixture()
	filter := f.tables[0]
	f.sets = map[string][]*nftables.Set{
		"filter": {
			{Table: filter, Name: "broken", ID: 1},
			{Table: filter, Name: "ok", ID: 2},
		},
	}
	f.elementsErr = map[string]error{"filter/broken": errors.New("no such file or directory")}
	f.elements = map[string][]nftables.SetElement{
		"filter/ok": {{Key: []byte{6}}},
	}

	rs, warns, err := readRuleset(f, nil, nil)
	if err != nil {
		t.Fatalf("readRuleset returned a hard error on a partial failure: %v", err)
	}
	if !rs.ReadFailed {
		t.Fatalf("ReadFailed must be set when a set's elements could not be read")
	}
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "broken") {
		t.Fatalf("warnings = %+v, want one naming the unreadable set", warns)
	}
	sets := rs.Tables[0].Sets
	if len(sets) != 1 || sets[0].Name != "ok" {
		t.Fatalf("sets = %+v, want only the set that read successfully", sets)
	}
}

// I6: the README claimed iptables-legacy hosts "are not read", but nothing
// detected them. On such a host ListTables succeeds against an empty nft
// ruleset and every port reports reachable with no warning at all.
func TestLegacyBackendIsDetectedAndWarnsLoudly(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "ip_tables_names"), []byte("nat\nfilter\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	warns := LegacyBackend(proc)
	if len(warns) != 1 {
		t.Fatalf("warnings = %+v, want exactly one", warns)
	}
	if warns[0].Source != "ruleset" {
		t.Fatalf("source = %q, want ruleset", warns[0].Source)
	}
	for _, want := range []string{"iptables-legacy", "filter", "incomplete"} {
		if !strings.Contains(warns[0].Message, want) {
			t.Fatalf("message = %q, missing %q", warns[0].Message, want)
		}
	}
}

// An nftables-only host has no such file, and a host where the module is
// loaded but carries no table must not be warned about either.
func TestLegacyBackendSilentOnAnNftablesHost(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if warns := LegacyBackend(proc); len(warns) != 0 {
		t.Fatalf("warnings = %+v, want none when the module is not loaded", warns)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "ip_tables_names"), []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warns := LegacyBackend(proc); len(warns) != 0 {
		t.Fatalf("warnings = %+v, want none when the file lists no table", warns)
	}
}

// Both families are checked, and each names its own backend.
func TestLegacyBackendDetectsIPv6Separately(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "ip6_tables_names"), []byte("filter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	warns := LegacyBackend(proc)
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "ip6tables-legacy") {
		t.Fatalf("warnings = %+v, want one naming the ip6 legacy backend", warns)
	}
}

// /proc/net/ip_tables_names is root-only, so an unprivileged run cannot tell
// whether legacy rules exist. A silent pass would be the same silent
// all-clear the check exists to prevent.
func TestLegacyBackendWarnsWhenItCannotCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, an unreadable file cannot be simulated")
	}
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(proc, "net", "ip_tables_names")
	if err := os.WriteFile(path, []byte("filter\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	warns := LegacyBackend(proc)
	if len(warns) != 1 || !strings.Contains(warns[0].Message, "could not check") {
		t.Fatalf("warnings = %+v, want one saying the check could not be made", warns)
	}
}

// /proc/net/ip_tables_names lists tables the ip_tables module has
// registered, which happens as soon as anything loads it: running
// `iptables -L` against an empty legacy ruleset is enough. The warning
// must not claim rules exist on that evidence, only that whyopen cannot
// see whether they do.
func TestLegacyBackendDoesNotClaimRulesItCannotSee(t *testing.T) {
	proc := t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "net", "ip_tables_names"), []byte("filter\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	msg := LegacyBackend(proc)[0].Message
	if strings.Contains(msg, "rules are present") {
		t.Errorf("message asserts rules exist on evidence that only shows a registered table: %q", msg)
	}
	// It still has to say what is at stake, and that whyopen cannot tell.
	for _, want := range []string{"registered", "cannot tell", "incomplete"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message = %q, missing %q", msg, want)
		}
	}
}

// A netdev table carries the ingress hook, which runs before prerouting
// and can drop a packet before any rule whyopen walks. It was skipped
// here as a family that "cannot carry inbound IP verdicts", which is
// exactly backwards: an ingress chain decides whether the packet exists
// at all for everything downstream. The integration suite caught this
// after the evaluator had already been taught to handle such a chain, so
// the fix was reachable only from a document that carried one.
func TestReadRulesetKeepsNetdevTables(t *testing.T) {
	dropPolicy := nftables.ChainPolicyDrop
	guard := &nftables.Table{Family: nftables.TableFamilyNetdev, Name: "guard"}
	f := &fakeNFT{
		tables: []*nftables.Table{guard},
		chains: map[nftables.TableFamily][]*nftables.Chain{
			nftables.TableFamilyNetdev: {{
				Name: "ingress-guard", Table: guard,
				Hooknum: nftables.ChainHookIngress, Policy: &dropPolicy,
			}},
		},
	}

	devs := map[chainKey][]string{
		{Family: uint8(nftables.TableFamilyNetdev), Table: "guard", Chain: "ingress-guard"}: {"eth0"},
	}
	rs, _, err := readRuleset(f, devs, nil)
	if err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if len(rs.Tables) != 1 {
		t.Fatalf("tables = %+v, want the netdev table kept", rs.Tables)
	}
	ch := rs.Tables[0].Chains[0]
	if ch.Hook != "ingress" {
		t.Fatalf("chain = %+v, want the ingress hook", ch)
	}
	// The devices come from the separate netlink read, correlated by
	// family, table and chain name, since the library never carries them.
	if len(ch.Devices) != 1 || ch.Devices[0] != "eth0" {
		t.Fatalf("devices = %v, want [eth0] from the chain device read", ch.Devices)
	}
}

// A chain the device read knows nothing about carries no devices, which
// the evaluator reads as "could see anything" rather than "sees nothing".
func TestReadRulesetLeavesDevicesEmptyWhenTheReadFoundNone(t *testing.T) {
	dropPolicy := nftables.ChainPolicyDrop
	guard := &nftables.Table{Family: nftables.TableFamilyNetdev, Name: "guard"}
	f := &fakeNFT{
		tables: []*nftables.Table{guard},
		chains: map[nftables.TableFamily][]*nftables.Chain{
			nftables.TableFamilyNetdev: {{
				Name: "ingress-guard", Table: guard,
				Hooknum: nftables.ChainHookIngress, Policy: &dropPolicy,
			}},
		},
	}
	rs, _, err := readRuleset(f, nil, nil)
	if err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if len(rs.Tables[0].Chains[0].Devices) != 0 {
		t.Fatalf("devices = %v, want none", rs.Tables[0].Chains[0].Devices)
	}
}

// arp and bridge stay out: neither can decide whether an inbound IP
// packet reaches a socket on this host, and carrying them would grow
// every facts document for nothing.
func TestReadRulesetStillSkipsArpAndBridge(t *testing.T) {
	arp := &nftables.Table{Family: nftables.TableFamilyARP, Name: "arpfilter"}
	br := &nftables.Table{Family: nftables.TableFamilyBridge, Name: "brfilter"}
	f := &fakeNFT{tables: []*nftables.Table{arp, br}}

	rs, _, err := readRuleset(f, nil, nil)
	if err != nil {
		t.Fatalf("readRuleset: %v", err)
	}
	if len(rs.Tables) != 0 {
		t.Fatalf("tables = %+v, want none", rs.Tables)
	}
}
