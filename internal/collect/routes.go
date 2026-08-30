//go:build linux

package collect

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// Routes reads the host's routing table from /proc, reduced to the prefix
// and device a fib lookup needs (docs/decisions/0012-fib-and-routes.md).
//
// It reads text files rather than adding a third netlink message type to
// the two decisions 0006 and 0007 fenced: the proc tables carry the
// destination and the device, which is all this question needs.
//
// Nothing here warns. A host with one family disabled legitimately has no
// table for it, and a route whyopen cannot read only ever costs it the
// ability to resolve a fib lookup, which leaves the verdict unknown: the
// same place it was before routes were read at all.
func Routes(procRoot string) ([]facts.Route, []facts.Warning) {
	var out []facts.Route
	out = append(out, readIPv4Routes(filepath.Join(procRoot, "net", "route"))...)
	out = append(out, readIPv6Routes(filepath.Join(procRoot, "net", "ipv6_route"))...)
	return out, nil
}

// readIPv4Routes parses /proc/net/route, whose addresses and masks are
// little-endian hex words rather than dotted quads.
func readIPv4Routes(path string) []facts.Route {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []facts.Route
	sc := bufio.NewScanner(f)
	for first := true; sc.Scan(); first = false {
		if first {
			continue // the header line
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 {
			continue
		}
		dest, ok := leHexIPv4(fields[1])
		if !ok {
			continue
		}
		mask, ok := leHexIPv4(fields[7])
		if !ok {
			continue
		}
		out = append(out, facts.Route{
			Dest:      dest.String(),
			PrefixLen: bits.OnesCount32(binary.BigEndian.Uint32(mask.AsSlice())),
			Family:    "ip",
			Device:    fields[0],
		})
	}
	return out
}

// leHexIPv4 reads the little-endian hex word /proc/net/route writes an
// address as: "0000000A" is 10.0.0.0, not 0.0.0.10.
func leHexIPv4(s string) (netip.Addr, bool) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(v))
	return netip.AddrFrom4(b), true
}

// readIPv6Routes parses /proc/net/ipv6_route, whose destination is 32 hex
// digits with no separators and whose prefix length is hex.
func readIPv6Routes(path string) []facts.Route {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []facts.Route
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		raw, err := hex.DecodeString(fields[0])
		if err != nil || len(raw) != 16 {
			continue
		}
		prefix, err := strconv.ParseUint(fields[1], 16, 8)
		if err != nil {
			continue
		}
		addr, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		out = append(out, facts.Route{
			Dest:      addr.String(),
			PrefixLen: int(prefix),
			Family:    "ip6",
			Device:    fields[9],
		})
	}
	return out
}
