//go:build linux

package collect

import (
	"strings"
	"testing"
)

// Real /proc/net/tcp shape. Address is hex, little-endian per 4-byte group.
// st 0A is TCP_LISTEN; st 01 (ESTABLISHED) must be skipped.
const procNetTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 21456 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 19283 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0BB8 0100007F:C1B2 01 00000000:00000000 00:00000000 00000000  1000        0 33445 1 0000000000000000 20 0 0 10 0
`

// A :: bind, which with bind_v6_only=0 also accepts IPv4, plus a bind on a
// real address. The all-zero address alone cannot distinguish per-4-byte-group
// reversal from whole-buffer reversal, which is the only interesting thing
// about the IPv6 form: B80D0120...10000000 is 2001:db8::10 read per group and
// ::10:0:0:0:2001:db8 read as one buffer.
const procNetTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F91 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 44556 1 0000000000000000 100 0 0 10 0
   1: B80D0120000000000000000010000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 44557 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNetTCPListenersOnly(t *testing.T) {
	got, err := ParseProcNet(strings.NewReader(procNetTCP), "ip", "tcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2 listeners (the established one must be skipped): %+v", len(got), got)
	}
	if got[0].BindIP != "127.0.0.53" || got[0].Port != 53 {
		t.Fatalf("socket 0 = %s:%d, want 127.0.0.53:53", got[0].BindIP, got[0].Port)
	}
	if got[1].BindIP != "0.0.0.0" || got[1].Port != 22 || got[1].Inode != 19283 {
		t.Fatalf("socket 1 = %+v, want 0.0.0.0:22 inode 19283", got[1])
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	got, err := ParseProcNet(strings.NewReader(procNetTCP6), "ip6", "tcp")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sockets, want 2: %+v", len(got), got)
	}
	if got[0].BindIP != "::" || got[0].Port != 8081 {
		t.Fatalf("socket 0 = %s:%d, want [::]:8081", got[0].BindIP, got[0].Port)
	}
	if got[1].BindIP != "2001:db8::10" || got[1].Port != 443 {
		t.Fatalf("socket 1 = %s:%d, want [2001:db8::10]:443; whole-buffer reversal would give ::10:0:0:0:2001:db8", got[1].BindIP, got[1].Port)
	}
}
