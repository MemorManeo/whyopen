# 0011: What a range actually compiles to, and what closes it

Date: 2026-08-30
Status: accepted
Resolves: `expr.Range`, deferred by
`docs/decisions/0004-firewalld-expressions.md` because that capture never
produced one, and listed under "After 1.0" in
`docs/superpowers/plans/NEXT.md`.

## Question

`tcp dport 1024-2048` was the last ordinary construct whyopen reported
`unknown`. Decision 0004 guessed `expr.Range` was the thing to decode and
then found no evidence for it, because nothing in a firewalld zone ruleset
writes a range. The guess was never tested, so this capture wrote four
range shapes deliberately and printed what the kernel stored.

## Evidence

Captured in CI (run `33318460615`, job `integration`,
`TestCaptureRanges`) on a GitHub Actions `ubuntu-24.04` runner. The
ruleset:

```
table inet cap {
	set ports_interval { type inet_service; flags interval
	                     elements = { 100-200, 8080 } }
	chain input {
		type filter hook input priority 0; policy accept;
		tcp dport 1024-2048 accept
		tcp dport != 3000-4000 accept
		tcp dport @ports_interval accept
		tcp dport { 5000-5100, 6000 } accept
	}
}
```

What came back:

| nft text | expressions |
|---|---|
| `tcp dport 1024-2048 accept` | `Meta, Cmp, Payload, Cmp, Cmp, Verdict` |
| `tcp dport != 3000-4000 accept` | `Meta, Cmp, Payload, Range, Verdict` |
| `tcp dport @ports_interval accept` | `Meta, Cmp, Payload, Lookup, Verdict` |
| `tcp dport { 5000-5100, 6000 } accept` | `Meta, Cmp, Payload, Lookup, Verdict` |

**A positive range is not a `Range` expression at all.** It compiles to two
ordered comparisons on the same register, which whyopen already decodes as
`gte` and `lte` and then refuses in the evaluator, where the code said
"ordered comparisons are used for ranges, which whyopen does not model
yet". The construct 0004 predicted would need a new decoder needs no
decoder: it needs the comparison whyopen already records to be evaluated.

**`expr.Range` is what a *negated* range compiles to.** `op=1` (neq),
`from=0bb8` (3000), `to=0fa0` (4000), both big-endian in the register's
width. The positive form never produced one, so a decoder written from
0004's guess would have closed the rarer half and left the common one open.

**A range inside a set is neither.** Both the named interval set and the
anonymous `{ 5000-5100, 6000 }` came back as ordinary `Lookup`
expressions against sets with `interval=true`, whose elements carry the
range in a representation whyopen was not reading:

```
set "ports_interval" interval=true keytype=inet_service/2 bytes
  elem key=1f91 intervalend=true      8081
  elem key=1f90 intervalend=false     8080
  elem key=00c9 intervalend=true       201
  elem key=0064 intervalend=false      100
  elem key=0000 intervalend=true         0
```

Intervals are stored as a start element and an **exclusive** end element,
flagged `intervalend`, and a single value is an interval one wide: `8080`
is `[8080, 8081)`. `KeyEnd` was empty on every element, so this kernel uses
the flag representation and not the `NFTA_SET_ELEM_KEY_END` one that
decision 0005 also carries. The elements arrived in descending order, so
order is not something to rely on.

## Decision

Close all three shapes, each against what was captured and nothing more.

**Evaluate ordered comparisons.** Registers hold big-endian values, so a
byte-wise comparison of equal-width slices is the numeric one, for ports
and for addresses alike. This closes the positive range, which is the
common form.

**Decode `expr.Range`**, both `eq` and `neq`, comparing the register
against the inclusive bounds. Only `neq` was observed, but `eq` is the same
expression with one field different and refusing it would mean refusing a
construct whyopen can read perfectly well.

**Read an interval set as intervals.** Elements sort ascending, a start
pairs with the next end above it, and membership is `start <= key < end`.
`facts.SetElement` gains the `IntervalEnd` flag it needs to say which is
which, which is additive and so does not move the schema version (decision
0010).

**Refuse what was not captured, as everywhere else here.** A start with no
end above it is refused rather than read as running to the top of the
range. That is exactly what an open-ended interval such as `1024-65535`
would look like, since its exclusive end wraps to 0 and becomes
indistinguishable from the zero sentinel: closing it needs its own
capture. An element carrying a `KeyEnd` is refused too, since that
representation was not observed and mixing the two would be a guess.

## Consequence

`tcp dport 1024-2048`, its negation, a named interval set and an anonymous
set containing a range all resolve. What remains `unknown` in this area is
an interval whose upper bound is the top of the type's range, and the two
set shapes decision 0005 already refuses for their own reasons.
