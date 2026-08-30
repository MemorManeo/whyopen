//go:build linux

package collect

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// chainMsg builds the shape the kernel sends for one chain in an
// NFT_MSG_GETCHAIN dump: the nfgenmsg header, then the chain attributes,
// with the hook nested inside them.
func chainMsg(t *testing.T, family uint8, table, chain string, hook []netlink.Attribute) netlink.Message {
	t.Helper()
	inner, err := netlink.MarshalAttributes(hook)
	if err != nil {
		t.Fatal(err)
	}
	attrs := []netlink.Attribute{
		{Type: unix.NFTA_CHAIN_TABLE, Data: []byte(table + "\x00")},
		{Type: unix.NFTA_CHAIN_NAME, Data: []byte(chain + "\x00")},
		{Type: unix.NFTA_CHAIN_HOOK | 0x8000, Data: inner}, // 0x8000 is NLA_F_NESTED
	}
	body, err := netlink.MarshalAttributes(attrs)
	if err != nil {
		t.Fatal(err)
	}
	header := []byte{family, unix.NFNETLINK_V0, 0, 0}
	binary.BigEndian.PutUint16(header[2:], 0)
	return netlink.Message{Data: append(header, body...)}
}

func TestParseChainDevicesReadsASingleDevice(t *testing.T) {
	msgs := []netlink.Message{chainMsg(t, unix.NFPROTO_NETDEV, "guard", "ingress-guard", []netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: []byte{0, 0, 0, 0}},
		{Type: unix.NFTA_HOOK_DEV, Data: []byte("eth0\x00")},
	})}
	got := parseChainDevices(msgs)
	key := chainKey{Family: unix.NFPROTO_NETDEV, Table: "guard", Chain: "ingress-guard"}
	if devs := got[key]; len(devs) != 1 || devs[0] != "eth0" {
		t.Fatalf("devices = %v, want [eth0]", got[key])
	}
}

// A netdev chain can be attached to several devices at once
// (devices = { eth0, eth1 }), which arrives as a nested list rather than
// the single-device attribute.
func TestParseChainDevicesReadsADeviceList(t *testing.T) {
	list, err := netlink.MarshalAttributes([]netlink.Attribute{
		{Type: nftaDeviceName, Data: []byte("eth0\x00")},
		{Type: nftaDeviceName, Data: []byte("eth1\x00")},
	})
	if err != nil {
		t.Fatal(err)
	}
	msgs := []netlink.Message{chainMsg(t, unix.NFPROTO_NETDEV, "guard", "multi", []netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: []byte{0, 0, 0, 0}},
		{Type: nftaHookDevs | 0x8000, Data: list},
	})}
	got := parseChainDevices(msgs)
	devs := got[chainKey{Family: unix.NFPROTO_NETDEV, Table: "guard", Chain: "multi"}]
	if len(devs) != 2 || devs[0] != "eth0" || devs[1] != "eth1" {
		t.Fatalf("devices = %v, want [eth0 eth1]", devs)
	}
}

// A chain with no device, which is every base chain in the ip families,
// contributes nothing rather than an empty entry: the evaluator reads a
// missing entry as "whyopen does not know", and an empty one would say
// the same thing less clearly.
func TestParseChainDevicesSkipsAChainWithNoDevice(t *testing.T) {
	msgs := []netlink.Message{chainMsg(t, unix.NFPROTO_IPV4, "filter", "INPUT", []netlink.Attribute{
		{Type: unix.NFTA_HOOK_HOOKNUM, Data: []byte{0, 0, 0, 1}},
		{Type: unix.NFTA_HOOK_PRIORITY, Data: []byte{0, 0, 0, 0}},
	})}
	if got := parseChainDevices(msgs); len(got) != 0 {
		t.Fatalf("devices = %v, want nothing recorded", got)
	}
}

// A chain of the same name in another table or another family is a
// different chain, and the two must not collide.
func TestParseChainDevicesKeepsFamiliesAndTablesApart(t *testing.T) {
	msgs := []netlink.Message{
		chainMsg(t, unix.NFPROTO_NETDEV, "a", "guard", []netlink.Attribute{
			{Type: unix.NFTA_HOOK_DEV, Data: []byte("eth0\x00")}}),
		chainMsg(t, unix.NFPROTO_NETDEV, "b", "guard", []netlink.Attribute{
			{Type: unix.NFTA_HOOK_DEV, Data: []byte("eth1\x00")}}),
		chainMsg(t, unix.NFPROTO_INET, "a", "guard", []netlink.Attribute{
			{Type: unix.NFTA_HOOK_DEV, Data: []byte("eth2\x00")}}),
	}
	got := parseChainDevices(msgs)
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3 distinct chains: %v", len(got), got)
	}
	if got[chainKey{unix.NFPROTO_NETDEV, "a", "guard"}][0] != "eth0" ||
		got[chainKey{unix.NFPROTO_NETDEV, "b", "guard"}][0] != "eth1" ||
		got[chainKey{unix.NFPROTO_INET, "a", "guard"}][0] != "eth2" {
		t.Fatalf("chains collided: %v", got)
	}
}

// A message whyopen cannot make sense of is skipped, not fatal: this
// refinement never gets to break a run that would otherwise work.
func TestParseChainDevicesSkipsAMessageItCannotRead(t *testing.T) {
	msgs := []netlink.Message{
		{Data: []byte{1}}, // too short even for the nfgenmsg header
		{Data: []byte{unix.NFPROTO_NETDEV, unix.NFNETLINK_V0, 0, 0, 9, 9, 9}}, // truncated attributes
	}
	if got := parseChainDevices(msgs); len(got) != 0 {
		t.Fatalf("devices = %v, want nothing", got)
	}
}
