# 0006: Read chain hook devices with netlink whyopen issues itself

Date: 2026-08-30
Status: accepted
Resolves: the ingress hook going blind, recorded as the first smaller item
in `docs/superpowers/plans/NEXT.md` after v0.4.0 and demonstrated by
`TestIngressChainOnAnotherDeviceIsStillUnknownToday` in
`test/integration/ruleset_test.go`.

## Question

v0.4.0 closed a hole in the dangerous direction: a base chain on the
ingress hook was named "prerouting" (its hook number, NF_NETDEV_INGRESS, is
also NF_INET_PRE_ROUTING) and then skipped as a table of the wrong family,
so whyopen reported ports reachable while the kernel dropped every packet
arriving on that device. The evaluator now refuses to draw a verdict while
an ingress chain could see the packet.

It refuses too widely. The hook is per device, and the evaluator narrows to
that device when the chain names one, but a chain collected from a live
kernel never names one. `github.com/google/nftables` writes `NFTA_HOOK_DEV`
when it *adds* a chain, and drops it when it reads one back:
`hookFromMsg` (v0.3.0, `chain.go`) decodes `NFTA_HOOK_HOOKNUM` and
`NFTA_HOOK_PRIORITY` and ignores every other attribute in the nested hook,
including both `NFTA_HOOK_DEV` and the `NFTA_HOOK_DEVS` list a
multi-device chain carries. `Chain.Device` is therefore always empty after
a read, and one ingress chain anywhere makes every port on the host
`unknown`.

That is the safe direction, and it is unusable. A host that filters at
ingress gets no answers at all from a tool whose entire value is answers.

Decisions 0001 and 0005 fixed the read surface as a whitelist of
`*nftables.Conn` methods, five today. No method on that type can produce
this attribute, because the library discards it before any caller sees a
chain. So the whitelist cannot be widened to solve this: the question is
whether whyopen may read netlink itself.

## Options

**Fork or vendor the library.** A fork of a security-relevant dependency,
maintained forever, to add one attribute to one parser. Rejected: the
maintenance burden is permanent and the change is four lines.

**Shell out to `nft --json list chains`.** Rejected on decision 0001's own
finding: the `nft` renderer and the netlink reading disagree, and 0001
chose netlink as the source of truth precisely because of it. Adding an
external binary to the runtime dependencies to reintroduce that
disagreement is the wrong direction twice over.

**Wait for upstream.** The right long-term answer and not mutually
exclusive with the one below, but it does not ship, and it puts the fix on
someone else's schedule.

**Read the attribute with a netlink dump whyopen issues itself.**
Chosen.

## Decision

whyopen may issue one read-only netlink request of its own, an
`NFT_MSG_GETCHAIN` dump, for the sole purpose of recovering the hook
devices the library discards. It is confined to
`internal/collect/chaindev.go`, and the rules around it are as narrow as
the method whitelist it sits beside:

- **One message type, one direction.** `NFT_MSG_GETCHAIN` with
  `NLM_F_REQUEST|NLM_F_DUMP`, the same shape the library's own
  `ListChainsOfTableFamily` sends. No `NLM_F_CREATE`, no `NLM_F_REPLACE`,
  no `NFT_MSG_NEW*` or `NFT_MSG_DEL*` of any kind, ever. A write from this
  file would be a bug of a different order than a wrong verdict, and the
  file exists to make that easy to audit: it is short, it constructs
  exactly one message, and the constant is spelled out at the construction
  site.
- **It reads one thing.** The parser extracts the family, table name,
  chain name and the hook's device list, and discards everything else in
  the message. Every other property of a chain keeps coming from the
  library, so this cannot become a second, divergent chain reader.
- **Its failure is not the ruleset's failure.** If the dump fails, for any
  reason, the devices are simply unknown and whyopen behaves exactly as
  v0.4.0 did: an ingress chain is treated as seeing every packet, which is
  the conservative answer, with a warning saying the refinement did not
  happen. It never sets `ReadFailed`, because failing to refine a ruleset
  is not failing to read one.
- **The same evidence rule as every decoder here.** The single-device
  attribute (`NFTA_HOOK_DEV`) and the multi-device list
  (`NFTA_HOOK_DEVS`/`NFTA_DEVICE_NAME`) are both parsed, and both are
  asserted against a real kernel by the integration suite rather than
  taken from the header alone. `NFTA_HOOK_DEVS` and `NFTA_DEVICE_NAME` are
  not in `golang.org/x/sys/unix`, so their values are written out with the
  kernel enum they come from named alongside.

`github.com/mdlayher/netlink` becomes a direct dependency. It already was
an indirect one, through the nftables library, which uses it for exactly
this: whyopen is not adding a new dependency to the build, it is naming
one it already has.

`facts.Chain.Device string` becomes `Devices []string`, because a netdev
chain can be attached to several devices at once (`devices = { eth0, eth1
}`) and a single string cannot say so. Nothing is lost by replacing rather
than adding: the old field was introduced in v0.4.0 and no live collection
ever set it, for the reason this record exists.

## Consequence

An ingress chain narrows to the devices it is attached to, so a chain on
one interface no longer makes every port on the host unknown. When the
device cannot be read the old, blunt behaviour is what remains, which
means this decision can only improve an answer, never worsen one.

The patch belongs upstream. When `google/nftables` reads the attribute
itself, `chaindev.go` and this decision's exception should be deleted
rather than kept as a second source of the same truth.
