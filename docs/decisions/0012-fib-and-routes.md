# 0012: Decode fib, and collect the routes one of its shapes needs

Date: 2026-08-30
Status: accepted
Resolves: the documented gap left by
`docs/decisions/0009-sending-packets.md`'s sibling work in v1.2, where a
real firewalld's reverse-path rule made every IPv6 verdict on such a host
`unknown`.

## Question

The firewalld CI job found one construct whyopen cannot decode, and it is
not obscure: firewalld installs

```
meta nfproto ipv6 fib saddr . mark . iif oif missing drop
```

in `filter_PREROUTING` by default. Prerouting is walked for every packet,
so one undecodable rule there makes every IPv6 verdict on the host
unknown. firewalld is one of the two front-ends this tool exists to be
useful behind.

## Evidence

Captured in CI (`TestCaptureFib`), applying firewalld's own rule beside
two plainer shapes:

| nft text | expression | following cmp |
|---|---|---|
| `meta nfproto ipv6 fib saddr . mark . iif oif missing drop` | `Fib{ResultOIF, FlagSADDR, FlagMARK, FlagIIF, FlagPRESENT}` | `eq 00000000` |
| `fib daddr type local accept` | `Fib{ResultADDRTYPE, FlagDADDR}` | `eq 02000000` |
| `fib saddr oif missing drop` | `Fib{ResultOIF, FlagSADDR, FlagPRESENT}` | `eq 00000000` |

Two different questions wear the same expression name.

`fib daddr type` returns an `RTN_*` value (`2` is `RTN_LOCAL`), and it is
the native spelling of the `addrtype dst-type LOCAL` match whyopen has
decoded through the xt path since v0.1. The model already answers it with
certainty: the destination is local when it is one of the host's own
addresses and unicast otherwise.

`fib ... oif` with `FlagPRESENT` returns 1 when the lookup finds a route
and 0 when it does not, and the rule compares it against 0 to mean
"missing". Answering that needs the routing table, which whyopen has never
collected.

## Decision

**Decode the address-type shape from what the model already knows.** No new
collection: `fib daddr type local` resolves exactly as the xt addrtype
match it mirrors, and refusing it while decoding its compatibility twin
would be an accident of which backend wrote the rule.

**Collect routes, and answer the presence shape conservatively.** Routes
come from `/proc/net/route` and `/proc/net/ipv6_route`, read as text
beside the sysctls in the host collector. That deliberately does not widen
the netlink read surface decisions 0006 and 0007 fenced: this needs a
destination and a device, which the proc files carry, and adding a third
netlink message type for it would buy nothing.

**whyopen concludes "present", never "missing".** It answers 1 only when
it finds a route matching the packet's source whose device is the
interface the packet arrived on (or any matching route, when the rule does
not ask about the input interface). In every other case it refuses and the
verdict is `unknown`.

That asymmetry is the whole point. Concluding "missing" would make the
rule match and the packet drop, which reports a port as `filtered`, and
whyopen would be doing that on a routing table it knows it may have read
incompletely: it does not read policy routing rules, VRFs, or multipath
next-hops. Reporting a port closed on incomplete evidence is the one
failure this tool must not have. Concluding "present" errs the other way,
toward reporting the packet as continuing, which over-reports exposure and
is safe.

**The mark is ignored, and that is recorded rather than hidden.**
firewalld's rule includes `mark` in the lookup key. whyopen's synthetic
packet carries no mark, so the lookup it models is the mark-0 one, which
is the ordinary table. A ruleset that routes by mark could therefore be
read too optimistically, in the safe direction.

**Every other fib shape stays unknown.** `fib ... oif` without
`FlagPRESENT` puts an interface index in the register, and
`ResultOIFNAME` puts a name; whyopen refuses both rather than invent a
value for a register something downstream will compare.

## Consequence

An ordinary firewalld host resolves on IPv6 as well as IPv4, and
`fib daddr type local` resolves whichever backend wrote it. A host whose
routing whyopen cannot follow still reports `unknown` there, which is what
it should do, and the CI census that found this rule now allows nothing:
the next construct firewalld reaches for is a finding again.
