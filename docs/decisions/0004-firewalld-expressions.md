# 0004: Native expressions a firewalld-shaped ruleset emits

Date: 2026-08-29
Status: accepted
Resolves: section 6.2 of `docs/superpowers/specs/2026-08-29-whyopen-v0.1-design.md`
("Native nftables expressions"), tracked as Task 8 of
`.superpowers/sdd/2026-08-29-whyopen-v0.1/`

## Question

UFW and Docker reach the kernel through iptables-nft, so they arrive as xt
compatibility expressions, which decision 0001 already inventoried and
0003 partly decoded. A firewalld host, or any hand-written nft ruleset,
goes straight to native nftables expressions instead, and whyopen has
almost no decoder for those: everything without a case in
`internal/collect/nftconv.go`'s `convertExpr` becomes `ExprUnknown`. That is
honest, but it makes whyopen close to useless on such a host.

The spec named a guess at what to decode (`expr.Ct`, `expr.Lookup`,
`expr.Range`) and said explicitly: "if the capture shows something else,
the capture wins." So this had to be captured, not reasoned from memory,
for the same reason 0001 and 0003 were: 0001 already found that the `nft`
text renderer and the netlink reading disagree in a way memory would not
have predicted, and there was no reason to trust memory over bytes here
either.

A full firewalld install in CI is heavy and its ruleset is what matters,
not the daemon, so the ruleset was written directly with `nft -f`, using
the constructs firewalld's nftables backend actually generates.

## Evidence

Captured in CI (run `33250979677`, job `integration`, `capture_test.go`) on
a GitHub Actions `ubuntu-24.04` hosted runner, with `nftables`/`iptables`
installed via `apt-get`, matching the versions decision 0001 recorded
(`nftables 1.0.9`). `TestCaptureFirewalldExpressions` applied this ruleset
in a namespace:

```
table inet whyopen_fw {
	set zone_public_ifaces { type ifname; elements = { "wan0" } }
	set zone_public_ports  { type inet_service; elements = { 22, 8080 } }

	chain filter_IN_public_allow {
		ct state { established, related } accept
		tcp dport @zone_public_ports accept
		meta l4proto { tcp, udp } counter accept
	}
	chain filter_IN_public_deny {
		tcp dport 31337 counter drop
	}
	chain filter_IN_public {
		jump filter_IN_public_allow
		jump filter_IN_public_deny
	}
	chain filter_INPUT_ZONES {
		iifname @zone_public_ifaces goto filter_IN_public
		goto filter_IN_public
	}
	chain filter_INPUT {
		type filter hook input priority filter + 10; policy accept;
		ct state established,related accept
		ct state invalid drop
		iifname "lo" accept
		jump filter_INPUT_ZONES
		reject with icmpx type admin-prohibited
	}
}
```

Each construct stands in for a real firewalld mechanism: `filter_INPUT`'s
`type filter hook input priority filter + 10; policy accept;` is firewalld's
actual base-chain declaration; `filter_INPUT` → `filter_INPUT_ZONES` →
`filter_IN_public` → `filter_IN_public_allow`/`_deny` is firewalld's real
zone-dispatch chain structure; `zone_public_ifaces` and `zone_public_ports`
are named sets standing in for firewalld's zone-interface and
zone-service sets; `ct state`, tested in both its comma-list and
brace-list forms deliberately, and `meta l4proto` are the match kinds the
spec named; `iifname` is tested both as a direct literal (`"lo"`) and via a
named-set lookup (`@zone_public_ifaces`), which turned out to matter (see
below). It applied and ran without any of the constructs I had been unable
to verify locally causing trouble; the one construct I was not confident
enough of to write blind, the generic `th dport` field match firewalld
uses for multi-protocol services, was deliberately left out and replaced
with a plain `meta l4proto { tcp, udp }` match, which needed no such
verification.

### The census

Aggregated across all 13 rules the capture found:

| decoded (whyopen already has a case) | count | unknown (`ExprUnknown`) | count |
|---|---|---|---|
| `*expr.Verdict` | 12 | `*expr.Lookup` | 4 |
| `*expr.Cmp` | 6 | `*expr.Ct` | 3 |
| `*expr.Meta` | 5 | | |
| `*expr.Bitwise` | 2 | | |
| `*expr.Counter` | 2 | | |
| `*expr.Payload` | 2 | | |
| `*expr.Reject` | 1 | | |

Two native expression types are undecoded on this ruleset, not three: no
`*expr.Range` appeared. The spec's guess named it as likely; this ruleset
never wrote a numeric range (a port range such as `1024-2048`, or an
interval-flagged set), so it had no way to appear. Its absence here says
nothing about whether firewalld ever emits one; a future capture that
writes a range explicitly is needed to settle that separately.

### `ct state` compiles two different ways, not one

The per-rule log (`capture_test.go:274`, one line per rule, listing chain,
handle and the Go type of every expression in order) makes visible
something the aggregate counts alone hide. The three `*expr.Ct` are not
interchangeable:

| rule (handle) | nft text | expressions returned |
|---|---|---|
| `filter_IN_public_allow` (9) | `ct state { established, related } accept` | `Ct`, `Lookup`, `Verdict` |
| `filter_INPUT` (18) | `ct state established,related accept` | `Ct`, `Bitwise`, `Cmp`, `Verdict` |
| `filter_INPUT` (19) | `ct state invalid drop` | `Ct`, `Bitwise`, `Cmp`, `Verdict` |

The comma-list form (handles 18 and 19, two of the three `Ct` occurrences)
compiles to the load-mask-compare trio: `Ct` loads the state register,
`Bitwise` masks it against the OR of the named flags, `Cmp` compares the
masked result. That is the same shape decision 0001 found for the xt
`conntrack` match's `StateMask`, just via the native expression instead of
the compatibility one.

The brace-list form (handle 9, the remaining `Ct` occurrence) compiles
differently: `Ct` loads the state register, then a `Lookup` tests
membership directly against an anonymous set of `{established, related}`,
with no `Bitwise` and no `Cmp` at all. Writing curly braces around the same
two flag names produces a different netlink shape for an equivalent
condition. A decoder for `Ct` therefore cannot assume one fixed follow-on
pattern; it has to recognise both the mask-and-compare idiom and the
set-lookup idiom as the same underlying match, or it will decode
`established,related` correctly while still reporting `unknown` for
`{ established, related }`, or the reverse.

The other two `Lookup` occurrences are unrelated to `ct state`: `handle 10`
(`tcp dport @zone_public_ports`, a discrete port-number set) and `handle 16`
(`iifname @zone_public_ifaces`, a discrete interface-name set). `handle 12`
(`meta l4proto { tcp, udp }`) is the fourth. None of the three
non-`ct`-state `Lookup`s pair with `Bitwise` or `Cmp` at all; each stands
alone as `Meta`/`Payload` (loading the field) followed directly by
`Lookup` (testing membership) and `Verdict`. That is consistent with
`Lookup` on a discrete-value field being self-contained, while `Ct` on a
flag field is not: `Ct` alone, in either of its two shapes, cannot be
interpreted without also decoding whichever expression follows it.

### The drop question: not observed here

The most valuable thing this capture could have found is a construct
present in the kernel's ruleset that `google/nftables` never returned at
all, because its `exprFromName` table (confirmed by reading
`v0.3.0/expr/expr.go`) returns `nil`, and its caller silently skips, any
expression name not in that table. Comparing the `nft -a list ruleset` text
against the per-rule Go type log, statement by statement, for all 13
rules: every rule's expression count and content is fully accounted for.
`tcp dport @zone_public_ports accept`, one visible statement plus a
verdict, returned exactly `Meta, Cmp, Payload, Lookup, Verdict`, matching
the hidden protocol-dependency check (`Meta`+`Cmp` for the implicit
`l4proto == tcp`) plus the port-set test (`Payload`+`Lookup`) plus the
verdict; no rule returned fewer expressions than its text implies. Handle
numbers 8 and 11 do not appear anywhere (tables, chains, sets and rules
each have their own handle sequence, and 4, for example, is both a table
handle and a chain handle in the same listing), but no rule is missing:
the text lists exactly the 13 rules the netlink walk found, at the same
handles, with the same content.

**This capture did not find a drop, and it should not be read as evidence
that one does not exist.** The vocabulary this ruleset exercised, `ct`,
`meta`, `cmp`, `payload`, `lookup`, `counter`, `verdict`, `reject`, is
exactly the vocabulary already present in `exprFromName`'s switch, because
those are the constructs the spec asked for. `exprFromName` has no case at
all for at least `rt`, `socket`, `dup`, `byteorder`, `tproxy`, `hash` used
as a raw statement, `xfrm`, and several others (see the full source list in
decision 0001's sibling investigation, or `expr.go` directly); none of
those appeared here because nothing in this ruleset was written to produce
them. A ruleset that deliberately included one, `socket transparent` or
`rt classid` for instance, is the only way to observe the drop directly,
and this task did not attempt that. What this capture does establish is
narrower but still real: for the specific expression vocabulary a
firewalld zone ruleset of this shape actually needs (ct state, named and
anonymous sets, meta l4proto, jumps, iifname), nothing was silently lost
between the kernel and whyopen's collector.

## Decision

Decode `Lookup` before `Ct` in v0.2.

**`Lookup` first.** It appeared in more rules (4 of 13) than `Ct` (3 of
13), and in three of its four occurrences it stood alone as the whole
match, needing nothing beyond itself and the set it references. It is also
a prerequisite for the brace-form of `ct state`, so decoding it is not
optional groundwork that only helps `Lookup`-only rules; it is load-bearing
for one of the two `Ct` shapes as well. `expr.Lookup` carries a set
reference (name for a named set, or an ID for an anonymous one), not the
set's elements, so decoding it requires the collector to also read set
contents, which it does not do today; this ruleset used both an `ifname`
set and an `inet_service` set, so both flavours need it, not just
anonymous sets as the spec's original phrasing allowed for.

**`Ct` second, and scoped to two shapes, not one.** `CtKeySTATE` is the
only key this capture exercised, and it requires recognising both the
mask-and-compare idiom (`Ct`, `Bitwise`, `Cmp`) and the set-lookup idiom
(`Ct`, `Lookup`), building on the `Lookup` decoder already in place for the
second one. Any other `CtKey` (`STATUS`, `MARK`, and the rest) is out of
scope until a capture exercises it; `ct status dnat`, which real firewalld
rulesets do use, was not written here.

**`Range` deferred indefinitely**, not scheduled, since this capture gives
no evidence it is needed. If a future capture (of a real firewalld
instance, an interval-flagged set, or an explicit port range) shows it in
use, that capture should drive the decision, not this one.

## Consequences

- v0.2's scope for native expression decoding is `Lookup` (named and
  anonymous sets, which requires the collector to read set elements) and
  `Ct` for `CtKeySTATE` in its two observed shapes. `Range` is out of scope
  until captured.
- Decoding `Ct` is decoding a multi-expression idiom, not a single
  expression; the decoder must not assume a fixed follow-on shape.
- This is one ruleset, one kernel, one `google/nftables` version (v0.3.0).
  The ruleset was written by hand to model what firewalld's nftables
  backend is documented and known to emit; it was never generated by a
  running `firewalld`, so a real firewalld installation could still differ
  in ways this capture cannot show, particularly for constructs this
  ruleset did not include: `ct status`, ICMP/ICMPv6 type lists, rate
  limiting beyond a bare counter, and interval sets.
- The "no drop observed" finding is scoped to the expression vocabulary
  this ruleset used. It is not evidence that `google/nftables` never drops
  an expression on a firewalld host; it only rules out a drop for the
  specific constructs captured here. A construct known to be outside
  `exprFromName` was never attempted, so the silent-discard failure mode
  the spec worried about remains untested, only better understood (its
  exact mechanism, `exprFromName` returning `nil` and the caller
  continuing past it, was confirmed by reading the library source, not by
  observing it happen).


## Update (v0.2)

`Ct` was decoded in v0.2, for the comma-list shape only, exactly the split
this record's decision anticipated. A native `ct state established,related
accept` or `ct state invalid drop` rule now decodes (`convertCt` in
`internal/collect/nftconv.go`, `CtKeySTATE` loaded into a destination
register) and resolves through the existing `Bitwise`/`Cmp` register
machine unchanged (`ctBytes` in `internal/model/match.go`), the
mask-and-compare idiom described above under "`ct state` compiles two
different ways, not one". `TestNativeCtStateAcceptResolvesReachable`
(`test/integration/ruleset_test.go`) proves it against a real kernel: a
`ct state established,related accept` rule now resolves a port `reachable`
instead of `unknown`.

The brace-list shape, `ct state { established, related } accept`, still
does not decode. It compiles to `Ct` plus `Lookup`, and `Lookup` has no
decoder yet, so decoding `Ct` alone was never going to close it; that is
exactly the dependency this record's decision named. `TestCaptureFirewalldExpressions`
was updated to hold this line precisely: `*expr.Ct` moved from the unknown
side of the census to the decoded side, `*expr.Lookup` did not move, and
the test fails again the day either fact stops being true.

## Update (v0.2, continued): `Lookup`

`Lookup` was decoded, closing the last gap this record named and completing
what the update above left open (both were always scoped to v0.2; no v0.3
work is implied by this section's numbering). It decodes
unconditionally (`convertLookup` in `internal/collect/nftconv.go`): nothing
about a `Lookup` expression's own fields marks it out of scope, only the
set it names can, and that set is not visible to the collector converting
one expression at a time. That judgement belongs entirely to
`internal/model/match.go`'s `lookupMatch`, which resolves a `Lookup` only
as a flat membership test against a set of equal-length keys, and refuses
everything else: an interval (range) set, a map or verdict map carrying a
value alongside each key, a concatenated key type, a set this document does
not carry at all, or a register narrower than the set's key width. Reading
a set's elements at all needed a fifth and sixth read-only method,
`GetSets` and `GetSetElements`, recorded separately in
`docs/decisions/0005-reading-set-elements.md` rather than assumed.

Decision 0004's own census found the kernel names a named set by string but
an anonymous one only by ID, never by a name reliable enough to match on
(`facts.Set.ID`, `facts.LookupExpr.SetID`); both are carried so the
anonymous case is resolvable at all, not just the named one.

This closes the dependency the "`ct state` compiles two different ways, not
one" section described: the brace-list shape, `ct state { established,
related } accept`, now decodes and resolves. It compiles to `Ct` then
`Lookup` against an anonymous set of the two ct-state flag values, no
`Bitwise` or `Cmp` involved, exactly as this record found back when neither
half decoded. `TestNativeSetLookupsResolveReachableAndFiltered`
(`test/integration/ruleset_test.go`) proves the anonymous-set form
(`tcp dport { 22, 80 } accept`), the named-set form
(`tcp dport @allowed_admin accept`) and the brace-list `ct state` idiom all
resolve against a real kernel, in one ruleset, deliberately run together so
that any one of the three failing to decode would poison the whole chain to
`unknown` rather than being masked by the other two.

`TestCaptureFirewalldExpressions` was updated again: `*expr.Lookup` moved
from the unknown side of the census to the decoded side alongside
`*expr.Ct`, and the test now also asserts nothing at all remains unknown
for this ruleset, since both native types it was written to exercise are
now decoded and decision 0004's own census accounted for every expression
this ruleset produces. The test fails again the day either type regresses
back to unknown, or some other expression in it stops decoding.

`Range` remains out of scope, unchanged from the original decision: no
capture has yet shown it in use.

The census and original decision above are left exactly as captured. Their
value is in being an honest record of what the capture found and what was
decided from it at the time, not in being edited to match what shipped
later; the two "Update" sections record what actually shipped against
that original record instead.
