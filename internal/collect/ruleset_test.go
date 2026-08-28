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
