# whyopen: what comes next

The core plan (`2026-08-28-whyopen-core.md`) is complete: `whyopen collect`
and `whyopen check` work against a real host. This file is the queue for the
work after it, in the order the work is worth doing. Written at the end of
the core plan so the reasoning survives.

The v0.1 plan (`2026-08-29-whyopen-v0.1.md`) then consumed three of these
entries: 3, 6 and 7, each marked below with what landed and what is left of
it rather than deleted, so the reasoning survives that plan too. Everything
unmarked is still queued.

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

## 3. Decode `xt recent` (landed in v0.1)

Done, and kept here because the reasoning is still the record of why. UFW's
`ufw limit ssh` emits it, so port 22 on a stock UFW host used to report
`unknown`, which was the most visible gap in the tool's output. The decoder
is in `internal/collect/nftconv.go` and the evaluator's `recent` case in
`internal/model/match.go`, written against bytes captured from a live kernel
and recorded in `docs/decisions/0003-xt-recent-layout.md` rather than from
memory, as this entry asked. `TestUFWLimitSSHResolvesReachable` proves port
22 resolves against a real kernel.

What is left of it: only the three captured `check_set` bit patterns decode.
`--remove` was never captured, so a `--remove` rule still reports `unknown`,
and closing that needs a fresh capture rather than an inference from the
pattern the other three follow.

## 4. Native nftables expression decoding

Captured, not speculative: `docs/decisions/0004-firewalld-expressions.md`
applied a firewalld-shaped ruleset in a namespace and recorded what
`google/nftables` actually returns. Decode `expr.Lookup` first (named and
anonymous sets; needs the collector to read set elements, which it does not
today), then `expr.Ct` for `CtKeySTATE`, which arrives as one of two
different shapes depending on whether the source used a comma list or a
brace list, both documented there. `expr.Range` is deferred: the capture
found no evidence it is needed. The nftables library silently discards any
expression name it has no case for before whyopen ever sees it; 0004's
"drop question" section records what was and was not tested for that.

## 5. Probe and reconcile

`whyopen probe --target <ip> --ports <spec>` run from anywhere, and
`whyopen check --probe-from ssh://host` shelling out to a second machine.
Merge probe results into the verdict set with the probe authoritative for
TCP, leave UDP model-only, and report disagreements between model and
reality as the headline diagnostic. This is also the answer for a host behind
NAT, where the model correctly refuses to conclude anything.

## 6. Network namespace integration harness in CI (landed in v0.1)

Built, and the motivation stands as the record of why: the committed golden
fixture covers realistic data, this covers configurations the author does
not run. `test/integration/` holds nine root-requiring tests behind the
`integration` build tag, documented in `test/integration/README.md` and run
by the `integration` job in `.github/workflows/ci.yml`. That job treats a
skip as a failure, because an unprivileged run skips every test and still
exits 0; it greps its own log for `--- SKIP` and fails on it, which is what
stops the suite from quietly never running.

Of the four fixtures this entry named, three exist as tests: a clean UFW
box (`TestUFWShapedRulesetAcceptsOnlyTheAllowedPort`) and a `DOCKER-USER`
deny (`TestDockerUserDenyOverridesThePublish`), which is also the mechanism
`chaifeng/ufw-docker` uses, so the spec's fixtures 4 and 5 collapse into
that one test rather than two. Beyond the list, the suite also covers the
canonical trap against both a namespace and a real Docker daemon, a
loopback-bound publish, a host with forwarding disabled, and `ufw limit
ssh` decoding against a live kernel.

Still not built: the spec's fixture 8, a dead publish, DNAT with no
listener behind it. Every test in the suite starts a listener, because
whyopen derives endpoints from listening sockets and Docker publishes, so a
publish with nothing behind it is precisely the case none of them
exercises.

## 7. Release (landed in v0.1)

Shipped: `.goreleaser.yaml` builds static (`CGO_ENABLED=0`) linux amd64 and
arm64 binaries into `tar.gz` archives, plus deb and rpm through nfpm
installing to `/usr/bin`, plus a `checksums.txt`. arm64 was not optional, as
this entry said: a large share of the audience runs Raspberry Pi hardware.
`.github/workflows/release.yml` runs GoReleaser on a `v*` tag, and
`cmd/whyopen` grew a `version` subcommand printing the version, commit and
build date injected at link time.

Outstanding. No tag has been pushed, so no release exists yet; the
machinery was verified by running GoReleaser locally rather than by a real
tag run. Three small gaps were found in review and deliberately deferred
rather than rushed into the tag:

- `wrap_in_directory` is not set on the archives, so a `tar.gz` extracts its
  contents into the current directory instead of a named one.
- The `version` subcommand has no `debug.ReadBuildInfo` fallback, so a
  binary from `go install` prints `dev` rather than a version.
- The release workflow does not run the tests before building. A tag that
  fails CI would still publish.

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
