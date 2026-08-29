//go:build linux

package collect

import (
	"net/netip"
	"strings"
	"testing"
)

func TestClassifyAddr(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10": "global",
		"172.17.0.1":   "private",
		"10.0.0.5":     "private",
		"192.168.1.1":  "private",
		"127.0.0.1":    "loopback",
		"::1":          "loopback",
		"2001:db8::10": "global",
		"fe80::1":      "link-local",
		"fd00::1":      "ula",
	}
	for in, want := range cases {
		ip := netip.MustParseAddr(in)
		if got := ClassifyAddr(ip); got != want {
			t.Fatalf("ClassifyAddr(%s) = %q, want %q", in, got, want)
		}
	}
}

// TestHostWarnsOnUnreadableSysctls covers the fix for a defect where an
// unreadable sysctl silently defaulted to false with nothing in the
// returned warnings saying it was never read.
func TestHostWarnsOnUnreadableSysctls(t *testing.T) {
	procRoot := t.TempDir() // no sys/net/... tree, so every sysctl read fails

	h, warns := Host(procRoot)

	if h.Sysctls.IPv4Forward || h.Sysctls.IPv6Forward || h.Sysctls.BindV6Only {
		t.Fatalf("sysctls = %+v, want all false when unreadable", h.Sysctls)
	}

	wantRels := []string{
		"sys/net/ipv4/ip_forward",
		"sys/net/ipv6/conf/all/forwarding",
		"sys/net/ipv6/bindv6only",
	}
	for _, rel := range wantRels {
		found := false
		for _, w := range warns {
			if w.Source == "host" && strings.Contains(w.Message, rel) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("warnings %+v do not name unreadable sysctl %q", warns, rel)
		}
	}
}
