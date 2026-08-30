//go:build linux

package collect

import (
	"encoding/binary"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// This file is the whole of decision 0006: the one netlink request
// whyopen issues itself, rather than through github.com/google/nftables.
//
// It exists because the library discards the attribute this reads.
// hookFromMsg decodes a chain hook's number and priority and drops
// everything else in the nested attribute, including the device an
// ingress or egress chain is attached to, so a chain read through the
// library never says which device it can see and whyopen has to treat
// every ingress chain as seeing every packet.
//
// It reads. It sends one NFT_MSG_GETCHAIN dump, the same message shape
// the library's own ListChainsOfTableFamily sends, and it extracts one
// thing. There is no NFT_MSG_NEW*, no NFT_MSG_DEL*, and no NLM_F_CREATE
// or NLM_F_REPLACE anywhere in this package, by rule and not by accident.

// Attribute values the kernel defines but golang.org/x/sys/unix does not
// export. From linux/netfilter/nf_tables.h: enum nft_hook_attributes has
// NFTA_HOOK_DEVS after NFTA_HOOK_DEV (which unix does export, as 0x3), and
// enum nft_devices_attributes has NFTA_DEVICE_NAME first after UNSPEC.
const (
	nftaHookDevs   = 4
	nftaDeviceName = 1
)

// nlaNested is NLA_F_NESTED, the flag the kernel sets on an attribute
// whose payload is itself a list of attributes.
const nlaNested = 0x8000

// chainKey identifies a chain the way the ruleset does: a chain name is
// unique only within its table, and a table name only within its family.
type chainKey struct {
	Family uint8
	Table  string
	Chain  string
}

// ChainDevices returns the devices each base chain's hook is attached to,
// for the chains that have any. A chain missing from the map is one whose
// devices whyopen does not know, which the evaluator reads as "could see
// anything" rather than "sees nothing".
//
// A failure here is never a failure to read the ruleset: it returns a
// warning and no devices, and whyopen falls back to the conservative
// answer it gave before it could read them at all.
func ChainDevices() (map[chainKey][]string, []facts.Warning) {
	c, err := netlink.Dial(unix.NETLINK_NETFILTER, nil)
	if err != nil {
		return nil, []facts.Warning{{Source: "ruleset", Message: fmt.Sprintf(
			"could not open netlink to read chain hook devices (%v), so an ingress chain is treated as seeing every packet and may make more verdicts unknown than it should", err)}}
	}
	defer c.Close()

	msg := netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType((unix.NFNL_SUBSYS_NFTABLES << 8) | unix.NFT_MSG_GETCHAIN),
			Flags: netlink.Request | netlink.Dump,
		},
		// nfgenmsg: family, version, res_id. AF_UNSPEC asks for every
		// family in one dump.
		Data: []byte{unix.AF_UNSPEC, unix.NFNETLINK_V0, 0, 0},
	}
	msgs, err := c.Execute(msg)
	if err != nil {
		return nil, []facts.Warning{{Source: "ruleset", Message: fmt.Sprintf(
			"could not read chain hook devices (%v), so an ingress chain is treated as seeing every packet and may make more verdicts unknown than it should", err)}}
	}
	return parseChainDevices(msgs), nil
}

// parseChainDevices pulls the family, table, chain and hook devices out of
// a chain dump and discards everything else in it. Every other property of
// a chain comes from the nftables library, so this cannot drift into being
// a second chain reader.
//
// A message it cannot read is skipped rather than fatal: this refinement
// never gets to break a run that would otherwise work.
func parseChainDevices(msgs []netlink.Message) map[chainKey][]string {
	out := map[chainKey][]string{}
	for _, m := range msgs {
		// nfgenmsg: family, version, res_id.
		if len(m.Data) < 4 {
			continue
		}
		key := chainKey{Family: m.Data[0]}
		var devices []string

		ad, err := netlink.NewAttributeDecoder(m.Data[4:])
		if err != nil {
			continue
		}
		ad.ByteOrder = binary.BigEndian
		for ad.Next() {
			switch ad.Type() {
			case unix.NFTA_CHAIN_TABLE:
				key.Table = ad.String()
			case unix.NFTA_CHAIN_NAME:
				key.Chain = ad.String()
			case unix.NFTA_CHAIN_HOOK:
				ad.Do(func(b []byte) error {
					devices = hookDevices(b)
					return nil
				})
			}
		}
		if ad.Err() != nil || key.Table == "" || key.Chain == "" || len(devices) == 0 {
			continue
		}
		out[key] = devices
	}
	return out
}

// hookDevices reads the device or devices out of a nested hook attribute.
// Both spellings exist: a single NFTA_HOOK_DEV for `device eth0`, and an
// NFTA_HOOK_DEVS list for `devices = { eth0, eth1 }`.
func hookDevices(b []byte) []string {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return nil
	}
	ad.ByteOrder = binary.BigEndian
	var out []string
	for ad.Next() {
		switch ad.Type() {
		case unix.NFTA_HOOK_DEV:
			out = append(out, ad.String())
		case nftaHookDevs:
			ad.Do(func(inner []byte) error {
				nested, err := netlink.NewAttributeDecoder(inner)
				if err != nil {
					return nil
				}
				nested.ByteOrder = binary.BigEndian
				for nested.Next() {
					if nested.Type() == nftaDeviceName {
						out = append(out, nested.String())
					}
				}
				return nil
			})
		}
	}
	if ad.Err() != nil {
		return nil
	}
	return out
}
