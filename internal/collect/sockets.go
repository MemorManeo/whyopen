//go:build linux

package collect

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// tcpListen is TCP_LISTEN in /proc/net/tcp's st column.
const tcpListen = "0A"

// Sockets reads every listening TCP and UDP endpoint. procRoot is "/proc" in
// production and a fixture directory in tests.
func Sockets(procRoot string) ([]facts.Socket, []facts.Warning) {
	var (
		all   []facts.Socket
		warns []facts.Warning
	)
	for _, src := range []struct{ file, family, proto string }{
		{"net/tcp", "ip", "tcp"},
		{"net/tcp6", "ip6", "tcp"},
		{"net/udp", "ip", "udp"},
		{"net/udp6", "ip6", "udp"},
	} {
		f, err := os.Open(filepath.Join(procRoot, src.file))
		if err != nil {
			warns = append(warns, facts.Warning{
				Source: "sockets", Message: fmt.Sprintf("open %s: %v", src.file, err),
			})
			continue
		}
		socks, err := ParseProcNet(f, src.family, src.proto)
		f.Close()
		if err != nil {
			warns = append(warns, facts.Warning{
				Source: "sockets", Message: fmt.Sprintf("parse %s: %v", src.file, err),
			})
			continue
		}
		all = append(all, socks...)
	}

	owners, ownerWarns := socketOwners(procRoot)
	warns = append(warns, ownerWarns...)
	for i := range all {
		if o, ok := owners[all[i].Inode]; ok {
			all[i].PID = o.pid
			all[i].Process = o.comm
			all[i].Unit = o.unit
			all[i].Container = o.container
		}
	}
	return all, warns
}

// ParseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} table. For TCP only
// sockets in LISTEN are returned; for UDP every unconnected socket is, since
// an unconnected UDP socket is a listener.
func ParseProcNet(r io.Reader, family, proto string) ([]facts.Socket, error) {
	var out []facts.Socket
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		local, remote, st := fields[1], fields[2], fields[3]

		if proto == "tcp" && st != tcpListen {
			continue
		}
		if proto == "udp" && !strings.HasSuffix(remote, ":0000") {
			continue // connected UDP socket, not a listener
		}

		ip, port, err := parseHexAddr(local)
		if err != nil {
			return nil, fmt.Errorf("address %q: %w", local, err)
		}
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		inode, _ := strconv.ParseUint(fields[9], 10, 32)

		out = append(out, facts.Socket{
			Family: family, Proto: proto,
			BindIP: ip.String(), Port: port,
			UID: uint32(uid), Inode: uint32(inode),
		})
	}
	return out, sc.Err()
}

// parseHexAddr decodes "3500007F:0035" or the 32-hex-digit IPv6 form. Each
// 4-byte group is stored in host byte order, so every group is reversed.
func parseHexAddr(s string) (netip.Addr, uint16, error) {
	host, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("missing port separator")
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	if len(raw)%4 != 0 || (len(raw) != 4 && len(raw) != 16) {
		return netip.Addr{}, 0, fmt.Errorf("unexpected address length %d", len(raw))
	}
	for g := 0; g < len(raw); g += 4 {
		raw[g], raw[g+3] = raw[g+3], raw[g]
		raw[g+1], raw[g+2] = raw[g+2], raw[g+1]
	}
	addr, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("bad address bytes")
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	return addr, uint16(port), nil
}

type owner struct {
	pid       int
	comm      string
	unit      string
	container string
}

// socketOwners maps socket inode to the process holding it, by scanning
// /proc/<pid>/fd for "socket:[<inode>]" links. Without root this sees only
// the caller's own processes, which is reported as a warning by the caller.
func socketOwners(procRoot string) (map[uint32]owner, []facts.Warning) {
	out := map[uint32]owner{}
	var warns []facts.Warning

	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return out, []facts.Warning{{Source: "sockets", Message: fmt.Sprintf("read %s: %v", procRoot, err)}}
	}
	denied := 0
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			denied++
			continue
		}
		var o *owner
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]"), 10, 32)
			if err != nil {
				continue
			}
			if o == nil {
				o = &owner{pid: pid, comm: readTrimmed(filepath.Join(procRoot, e.Name(), "comm"))}
				o.unit, o.container = parseCgroup(readTrimmed(filepath.Join(procRoot, e.Name(), "cgroup")))
			}
			out[uint32(inode)] = *o
		}
	}
	if denied > 0 {
		warns = append(warns, facts.Warning{
			Source:  "sockets",
			Message: fmt.Sprintf("could not read fds of %d processes, run as root to attribute every socket", denied),
		})
	}
	return out, warns
}

func readTrimmed(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parseCgroup extracts a systemd unit or a Docker container id from the
// cgroup v2 path, for example
// "0::/system.slice/webapp-music-backend.service" or
// "0::/system.slice/docker-<64 hex>.scope".
func parseCgroup(s string) (unit, container string) {
	for _, line := range strings.Split(s, "\n") {
		path := line
		if i := strings.LastIndex(line, ":"); i >= 0 {
			path = line[i+1:]
		}
		for _, seg := range strings.Split(path, "/") {
			switch {
			case strings.HasPrefix(seg, "docker-") && strings.HasSuffix(seg, ".scope"):
				container = strings.TrimSuffix(strings.TrimPrefix(seg, "docker-"), ".scope")
			case strings.HasSuffix(seg, ".service"):
				unit = seg
			}
		}
	}
	return unit, container
}
