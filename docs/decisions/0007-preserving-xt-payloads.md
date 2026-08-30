# 0007: Read xt payloads from the rule dump, so no facts document is lossy

Date: 2026-08-30
Status: accepted
Extends: `docs/decisions/0006-reading-chain-devices.md`, which permitted the
first netlink request whyopen issues itself and fenced it to one message
type.

## Question

v0.4.0 made a facts document keep the payload of an extension whyopen
could not decode, so a later build with a better decoder can re-evaluate an
older snapshot. It only half worked, and the half it missed was recorded
honestly in `facts.XtExpr.Raw`'s own comment: the payload is kept for every
extension whose bytes reach whyopen, and the bytes reach whyopen only for
extensions `github.com/google/nftables` has no type for. For the ones it
does type, conntrack, addrtype and DNAT among them, the library consumes
the `NFTA_MATCH_INFO` or `NFTA_TARGET_INFO` blob and hands over a parsed
struct. whyopen never sees the bytes and cannot keep what it never saw.

That matters because those three are exactly where whyopen's own decoders
have been wrong before. Decision 0001 found the addrtype invert flags being
ignored, evaluating an inverted rule with inverted semantics at full
confidence; v0.4.0 found addrtype masks with types whyopen cannot name
being silently reduced. Each fix improved the decoder, and neither could be
applied to a single already-collected document, because the evidence had
been thrown away at collection time. A bug report with a facts document
attached, which is the workflow this tool documents, is worth less than it
should be for precisely the extensions most likely to be misread.

1.0 freezes the schema. A schema that cannot carry the evidence for its
most error-prone field is the wrong thing to freeze.

Re-marshalling the library's parsed struct back to bytes was considered in
v0.4.0 and rejected then for the reason it is rejected now: a marshal round
trip is not guaranteed to reproduce what the kernel sent, and recording a
payload whyopen never received, as though it had, is the exact species of
invention every decoder in this project refuses.

## Decision

Extend decision 0006's exception by one message type. whyopen may also
issue an `NFT_MSG_GETRULE` dump, read-only, for the sole purpose of
recovering the `NFTA_MATCH_INFO` and `NFTA_TARGET_INFO` payloads the
library consumes. Everything 0006 fenced still holds and now covers two
message types rather than one: request and dump flags only, no
`NFT_MSG_NEW*`, no `NFT_MSG_DEL*`, no `NLM_F_CREATE`, no `NLM_F_REPLACE`,
confined to `internal/collect`, and reading one thing while every other
property of a rule keeps coming from the library.

**Correlation is by position among xt expressions, not by position in the
expression list.** The library drops any expression whose name it has no
type for (`expr.go`'s `exprFromName` returns nil and its caller
`continue`s, which decision 0004 recorded as the "drop question"), so the
list whyopen receives can be shorter than the kernel's and index `i` in one
is not index `i` in the other. Both `match` and `target` are always typed,
so the *k*-th xt expression whyopen holds is the *k*-th xt expression the
kernel sent, and that correspondence is the one this uses. It is checked
rather than assumed: a payload is attached only when the name and revision
at that position agree, and dropped silently when they do not, because
attaching the wrong bytes to an expression would be worse than attaching
none.

**A payload is not a decode.** Keeping the bytes changes what the document
carries, not what any verdict says. The collector's decoders run exactly as
before.

**With bytes present, the reading build decodes.** `collect.Redecode` used
to fill in only what the collecting build left undecoded, on the reasoning
that the collecting build saw the live kernel and the reading one is
reading a file. That reasoning does not survive the payload being kept: the
bytes *are* what the collecting build saw, so a reading build with a better
decoder is strictly better placed, not worse. Redecode now re-derives every
xt expression that carries a payload, through the library's own
`xt.Unmarshal` and the same conversion the collector uses, so one document
read by two builds differs exactly as their decoders differ. Where there
are no bytes, the collector's answer still stands untouched, because
nothing can check it.

## Consequence

Every xt extension in a document collected from v0.5.0 on carries the
payload the kernel sent. The addrtype and conntrack fixes this project has
already made once, and any it makes later, become applicable to snapshots
taken before them. `--explain` on an old document can be re-read by a newer
build at that build's fidelity, which is what "collect once, evaluate
later" was supposed to mean.

The cost is one more dump per collection and the bytes themselves in the
document, which are small: an xt payload is tens of bytes, and the
committed 275-rule fixture host carries 156 of them.

Native nftables expressions are still not preserved this way. The library
hands those over as typed Go values too, but there is no single opaque blob
behind them to keep, and the parts whyopen does not decode are already
recorded as `ExprUnknown` with the type name. That is a different problem
and this record does not address it.
