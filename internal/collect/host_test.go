//go:build linux

package collect

import (
	"net/netip"
	"testing"
)

func TestClassifyAddr(t *testing.T) {
	cases := map[string]string{
		"159.195.9.107":      "global",
		"172.17.0.1":         "private",
		"10.0.0.5":           "private",
		"192.168.1.1":        "private",
		"127.0.0.1":          "loopback",
		"::1":                "loopback",
		"2a0a:4cc0:ff:492::": "global",
		"fe80::1":            "link-local",
		"fd00::1":            "ula",
	}
	for in, want := range cases {
		ip := netip.MustParseAddr(in)
		if got := ClassifyAddr(ip); got != want {
			t.Fatalf("ClassifyAddr(%s) = %q, want %q", in, got, want)
		}
	}
}
