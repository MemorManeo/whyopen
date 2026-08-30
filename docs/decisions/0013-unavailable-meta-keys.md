# 0013: A meta key with no value breaks the rule, it does not read as zero

Date: 2026-08-30
Status: accepted
Resolves: `meta skuid` leaving every verdict below it unknown, found by the
hand-written ruleset census.

## Question

`meta skuid` names the owner of the socket a packet belongs to. It is a
natural thing to write, and it appears in hand-written chains. whyopen
refused it, so one such rule made every port on the host unknown.

Two things had to be settled, and only one of them is about whether the
key can be modelled at all.

## Evidence

Asked by experiment rather than from documentation, in CI
(`TestCaptureSkuidOnInput`): a chain that drops by default and accepts
only `meta skuid 0`, a listener owned by root behind it, and a real probe
across the veth from another namespace.

The port came back **filtered**. The match did not fire, even though the
socket behind it is owned by uid 0, because on the input path the socket
has not been looked up when the filter hook runs. There is no owner to
compare against.

## Decision

**`meta skuid` and `meta skgid` resolve to a rule that does not match**, on
every hook whyopen walks.

The second thing that had to be settled is the shape of that answer, and
getting it wrong would have been worse than refusing. The obvious
implementation is to put zero in the register and let the comparison run.
That would make `meta skuid 0 accept` **match**, since zero equals zero,
and the experiment says it does not. An unavailable meta key does not
produce a value at all: it breaks the rule, which cannot then match
whatever the comparison would have said. So the model returns no-match for
the rule rather than a value for the register.

**The evidence covers input, and forward follows from something stronger.**
The capture was taken on the input hook. whyopen also walks forward, where
a packet is never delivered locally at all, so there is no socket there by
construction rather than by timing.

**Only these two keys.** Every other meta key whyopen does not model stays
refused. This is not a general rule that unknown metadata is absent; it is
two keys whose absence on these paths was established.

## Consequence

A chain carrying `meta skuid` resolves instead of poisoning every verdict
below it. The direction is also the safe one where it matters: a
`meta skuid ... drop` rule is read as not dropping, which over-reports
exposure rather than hiding it.
