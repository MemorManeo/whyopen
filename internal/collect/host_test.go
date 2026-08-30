//go:build linux

package collect

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/facts"
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

// Forwarding is a per-device flag, so the collector has to read the device
// files, not just the global toggle. lo is used because it is the one
// interface every host running this test is guaranteed to have.
func TestHostReadsPerInterfaceForwarding(t *testing.T) {
	root := t.TempDir()
	for rel, val := range map[string]string{
		"sys/net/ipv4/ip_forward":          "0",
		"sys/net/ipv6/conf/all/forwarding": "0",
		"sys/net/ipv6/bindv6only":          "0",
		"sys/net/ipv4/conf/lo/forwarding":  "1",
		"sys/net/ipv6/conf/lo/forwarding":  "1",
	} {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(val+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	h, warns := Host(root)
	var lo *facts.Interface
	for i := range h.Interfaces {
		if h.Interfaces[i].Name == "lo" {
			lo = &h.Interfaces[i]
		}
	}
	if lo == nil {
		t.Skip("no loopback interface on this host")
	}
	if !lo.IPv4Forwarding || !lo.IPv6Forwarding {
		t.Errorf("lo forwarding = ipv4:%v ipv6:%v, want both true", lo.IPv4Forwarding, lo.IPv6Forwarding)
	}
	// An interface with no conf file is the normal case (ipv6 disabled, or
	// a device that went away mid-read) and must not produce a warning:
	// the value only ever widens what whyopen calls reachable, so failing
	// to read one falls back to the global toggle and can never invent
	// forwarding that is not there.
	for _, w := range warns {
		if strings.Contains(w.Message, "conf/") {
			t.Errorf("per-interface read produced a warning: %s", w.Message)
		}
	}
}
