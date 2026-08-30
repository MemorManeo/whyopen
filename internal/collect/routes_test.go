//go:build linux

package collect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProcFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// /proc/net/route writes its addresses as little-endian hex, so the
// default route's 00000000 and a 10.0.0.0/8's 0000000A are the same field
// read the same way. Getting that backwards would match the wrong routes.
func TestRoutesReadsIPv4(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "net/route", `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
eth0	00000000	0100000A	0003	0	0	100	00000000	0	0	0
eth0	0000000A	00000000	0001	0	0	100	000000FF	0	0	0
docker0	000011AC	00000000	0001	0	0	0	0000FFFF	0	0	0
`)
	routes, warns := Routes(root)
	if len(warns) != 0 {
		t.Errorf("warnings = %+v, want none", warns)
	}
	want := []struct {
		dest   string
		prefix int
		dev    string
	}{
		{"0.0.0.0", 0, "eth0"},
		{"10.0.0.0", 8, "eth0"},
		{"172.17.0.0", 16, "docker0"},
	}
	if len(routes) != len(want) {
		t.Fatalf("routes = %+v, want %d", routes, len(want))
	}
	for i, w := range want {
		r := routes[i]
		if r.Dest != w.dest || r.PrefixLen != w.prefix || r.Device != w.dev || r.Family != "ip" {
			t.Errorf("route %d = %+v, want %s/%d on %s", i, r, w.dest, w.prefix, w.dev)
		}
	}
}

// /proc/net/ipv6_route writes the address as 32 hex digits with no colons
// and the prefix length as hex.
func TestRoutesReadsIPv6(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "net/ipv6_route",
		"00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000000 00000000 00000003 eth0\n"+
			"20010db8000004920000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000002 00000000 00000001 eth0\n")
	routes, warns := Routes(root)
	if len(warns) != 0 {
		t.Errorf("warnings = %+v, want none", warns)
	}
	if len(routes) != 2 {
		t.Fatalf("routes = %+v, want 2", routes)
	}
	if routes[0].Dest != "::" || routes[0].PrefixLen != 0 || routes[0].Device != "eth0" || routes[0].Family != "ip6" {
		t.Errorf("route 0 = %+v, want the default route on eth0", routes[0])
	}
	if routes[1].Dest != "2001:db8:0:492::" || routes[1].PrefixLen != 64 {
		t.Errorf("route 1 = %+v, want 2001:db8:0:492::/64", routes[1])
	}
}

// A missing file is the ordinary case for a host with one family disabled,
// and it must not warn: the value only ever lets whyopen resolve more, so
// its absence falls back to refusing, which is where it started.
func TestRoutesIsSilentWhenAFileIsMissing(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "net/route", "Iface\tDestination\n")
	routes, warns := Routes(root)
	if len(routes) != 0 {
		t.Errorf("routes = %+v, want none", routes)
	}
	if len(warns) != 0 {
		t.Errorf("warnings = %+v, want none for a missing ipv6 table", warns)
	}
}

// A line whyopen cannot parse is skipped rather than fatal, and rather
// than recorded as a route to somewhere it is not.
func TestRoutesSkipsAnUnreadableLine(t *testing.T) {
	root := t.TempDir()
	writeProcFile(t, root, "net/route", `Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask
eth0	notahexnumber	00000000	0001	0	0	0	000000FF
eth0	0000000A	00000000	0001	0	0	0	000000FF
short	line
`)
	routes, _ := Routes(root)
	if len(routes) != 1 || routes[0].Dest != "10.0.0.0" {
		t.Fatalf("routes = %+v, want only the readable one", routes)
	}
}
