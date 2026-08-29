# whyopen: what comes next

The core plan (`2026-08-28-whyopen-core.md`) is complete: `whyopen collect`
and `whyopen check` work against a real host. This file is the queue for the
second plan, in the order the work is worth doing. Written at the end of the
core plan so the reasoning survives.

Known gaps that motivate several of these are recorded separately in
`docs/decisions/0002-known-gaps-and-follow-up.md`.

## 1. Policy file and exit codes

The piece that turns a one-off audit into a guardrail, and the reason the
exit codes already exist.

- `whyopen.yaml` with a `zones.internet.allow` list and `fail_on_unknown`.
- `whyopen policy init` generating it from the current state, so adoption is
  one command plus an edit.
- Exit 1 on a policy violation, exit 2 on unknown verdicts when
  `fail_on_unknown` is set. Exit 0 and exit 3 are already wired.
- A reachable port not in the allow list is a violation; an allowed port that
  is not reachable is reported at info level and does not fail.

## 2. `--json` output

A stable, versioned schema for the verdict set, so the tool composes with
other things. Blocked on one small decision: `Verdict.DNAT` is currently an
exported field of an unexported type, which has to become exportable before
it can be serialised.

## 3. Decode `xt recent`

The single highest-value decoder left. UFW's `ufw limit ssh` emits it, so on
a stock UFW host port 22 reports `unknown` today, which is the most visible
gap in the tool's output. Needs `xt_recent_mtinfo` decoded well enough to
tell `--set` (always matches, no constraint) from `--update --seconds N
--hitcount M` (cannot match a first packet from an unseen source). Verify the
struct offsets against real bytes rather than from memory.

## 4. Native nftables expression decoding

`expr.Ct`, `expr.Lookup` (anonymous and named sets) and `expr.Range` cover
most of what a hand-written nft ruleset or a firewalld host emits. Without
them those hosts report `unknown` widely, which is honest but not useful.
Note that the nftables library discards expressions it cannot name before
whyopen sees them, so some cases cannot be fixed here at all.

## 5. Probe and reconcile

`whyopen probe --target <ip> --ports <spec>` run from anywhere, and
`whyopen check --probe-from ssh://host` shelling out to a second machine.
Merge probe results into the verdict set with the probe authoritative for
TCP, leave UDP model-only, and report disagreements between model and
reality as the headline diagnostic. This is also the answer for a host behind
NAT, where the model correctly refuses to conclude anything.

## 6. Network namespace integration harness in CI

Build real netns and veth topologies, apply real rulesets, and assert
verdicts against them. This unlocks the spec's remaining fixtures that cannot
be captured from a single host: a clean UFW box, a ufw-docker-applied host, a
`DOCKER-USER` deny rule, and a dead publish with no listener behind it. The
committed golden fixture covers realistic data; this covers configurations
the author does not run.

## 7. Release

GoReleaser, static amd64 and arm64 binaries, deb and rpm. arm64 is not
optional: a large share of the audience runs Raspberry Pi hardware.

## Smaller items, roughly in value order

- Validate `--facts` input at the boundary; a hand-crafted document can
  currently reach a nil dereference.
- Mark an `addrtype` match undecoded when its mask carries a bit whyopen has
  no name for, the same way the invert flags are now handled.
- Read per-interface forwarding, not just the global toggle.
- Name and model the ingress hook rather than letting it poison every verdict.
- Record a `Hit` for a rule skipped as harmless, so `--explain` shows it.
- Render IPv6 addresses properly in `--explain`; they currently print as hex.
- Detect iptables-legacy more precisely: a registered table is not the same
  as a table with rules in it.
- Preserve the raw payload of an extension the collector cannot decode,
  instead of recording only `decoded: false` and discarding the bytes. A
  facts document is currently lossy for anything the capturing build could
  not decode: a later build with a better decoder cannot re-evaluate an
  older snapshot at its improved fidelity, which weakens both the
  collect-once-evaluate-later premise and the documented bug-report
  workflow where a user attaches a facts document. Found while shipping xt
  recent decoding, whose own golden fixture predates the decoder and so
  could not benefit from it.
