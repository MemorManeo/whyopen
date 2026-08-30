# whyopen: what comes next

**The queue below is empty as of v1.0.0.** Every numbered entry landed and
every smaller item is done or explicitly refused, each marked in place
rather than deleted so the reasoning survives. What is genuinely still
open, and what 1.0 deliberately shipped without, is the short list at the
bottom under "After 1.0".

The core plan (`2026-08-28-whyopen-core.md`) is complete: `whyopen collect`
and `whyopen check` work against a real host. This file is the queue for the
work after it, in the order the work is worth doing. Written at the end of
the core plan so the reasoning survives.

The v0.1 plan (`2026-08-29-whyopen-v0.1.md`) then consumed three of these
entries: 3, 6 and 7, each marked below with what landed and what is left of
it rather than deleted, so the reasoning survives that plan too. v0.2 took
entry 4, v0.3 entry 1, and v0.4 entries 2 and 5 plus every item in the
smaller list, marked the same way. Everything unmarked is still queued.

Known gaps that motivate several of these are recorded separately in
`docs/decisions/0002-known-gaps-and-follow-up.md`.

## 1. Policy file and exit codes (landed in v0.3)

The piece that turns a one-off audit into a guardrail, and the reason the
exit codes already exist. Everything this entry asked for is in:
`whyopen.yaml` exactly as section 8 of the design spec drew it,
`whyopen policy init`, exit 1 on a violation, exit 2 on unknowns when
`fail_on_unknown` is set, and a stale allow entry reported without failing
the run.

It lives in `internal/policy` (`Load`, `Check`, `Init`, `Marshal`), pure
over `[]model.Verdict` and importing nothing but the stdlib,
`internal/model` and the YAML parser, so the whole subsystem tests without
root or a kernel and needs no integration tier. `internal/model` gained
nothing: what the kernel does and what the operator wanted stay in
separate packages, which is the same separation that makes an `unknown`
verdict trustworthy. `cmd/whyopen`'s `checkExitCode` now ranks the
outcomes, an unreadable ruleset over a violation over an unknown, and
`report.Policy` prints the block that gives every non-zero exit a visible
reason.

Two judgement calls worth recording. A generated policy sets
`fail_on_unknown: true`, so on a host with unresolved ports the very next
`check --policy` exits 2: a guardrail that ignores what it cannot see is a
false green, and `policy init` names those ports in a comment so the
failure is not a surprise. And `policy init` refuses to overwrite an
existing file, unlike `collect -o`, because a policy carries human edits
that a facts document does not.

`github.com/goccy/go-yaml` is the first dependency whyopen has taken that
is not the netlink stack. It was chosen over the ubiquitous
`gopkg.in/yaml.v3` because that module is archived upstream and its last
release is v3.0.1 from May 2022, while goccy is current and its `go.mod`
declares no dependencies of its own, so the module graph grows by exactly
one node.

What is left: the allow list has no address family (`443/tcp` covers both)
and no port ranges, `zones` has exactly one meaningful key because
`model.InternetZone()` is the only zone whyopen models, and there is no
implicit config discovery: without `--policy` no policy is consulted.
Each of those is a deliberate refusal to invent a surface before someone
needs it. Entry 2's `--json` will have to carry the policy result too, or
a machine reader gets the verdicts without the judgement on them.

## 2. `--json` output (landed in v0.4)

`whyopen check --json` writes a versioned document: schema_version, the
build, the hostname, the zone, every verdict, the collection warnings, the
policy result when one was given, and the probe disagreements when one was
run. The rule path is included only under `--explain`, which narrows the
document to one port exactly as it narrows the text output.

The document is its own shape rather than the model's structs marshalled,
because a schema that is just internal types would change whenever they
were refactored and this one is a promise. Its schema_version is its own
number too: the facts document describes what was collected, this one what
was concluded.

The blocker this entry named, `Verdict.DNAT` being an exported field of an
unexported type, was real but not for the reason given: with the output
shape separate, nothing needed to marshal that type. It was exported so a
test could construct a rewritten verdict.

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

## 4. Native nftables expression decoding (`Ct` and `Lookup` landed in v0.2)

Captured, not speculative: `docs/decisions/0004-firewalld-expressions.md`
applied a firewalld-shaped ruleset in a namespace and recorded what
`google/nftables` actually returns. The plan there was to decode
`expr.Lookup` first (named and anonymous sets; needs the collector to read
set elements, which it does not today), then `expr.Ct` for `CtKeySTATE`,
which arrives as one of two different shapes depending on whether the
source used a comma list or a brace list, both documented there. `expr.Range`
is deferred: the capture found no evidence it is needed. The nftables
library silently discards any expression name it has no case for before
whyopen ever sees it; 0004's "drop question" section records what was and
was not tested for that.

What landed, out of the order that plan named: `Ct` for `CtKeySTATE`'s
comma-list shape (`ct state established,related accept`, `ct state invalid
drop`), decoded in `internal/collect/nftconv.go` and resolved through the
existing `Bitwise`/`Cmp` machinery already in `internal/model/match.go`,
proven against a real kernel by `TestNativeCtStateAcceptResolvesReachable`.
See `docs/decisions/0004-firewalld-expressions.md`'s own "Update (v0.2)"
section for detail.

What landed next, completing v0.2's scope for this entry: `expr.Lookup`,
decoded unconditionally in `internal/collect/nftconv.go` (`convertLookup`);
whether it resolves depends on the set it names, which
`internal/model/match.go`'s `lookupMatch` decides, as a flat membership
test only, refusing an interval set, a map or verdict map, a concatenated
key type, or a set the document does not carry. Reading a set's elements
at all needed two more read-only methods, `GetSets` and `GetSetElements`,
recorded in `docs/decisions/0005-reading-set-elements.md`. This closes the
brace-list `ct state` shape too, since it depends on both decoders (`Ct`
then `Lookup`, no `Bitwise`/`Cmp`), proven together against a real kernel
by `TestNativeSetLookupsResolveReachableAndFiltered`. See
`docs/decisions/0004-firewalld-expressions.md`'s own "Update (v0.2,
continued): `Lookup`" section for detail.

What is left: `expr.Range` is still undecoded, deferred since decision
0004's capture found no evidence it is needed; a numeric range or an
interval-flagged set still reports `unknown`. A set whose elements
whyopen cannot interpret as a flat list, a map, a vmap, or a concatenated
key type, are all deliberate refusals rather than gaps: closing any of
those needs a captured ruleset that actually exercises the shape, the same
evidence-first posture every decoder in this project has followed.

## 5. Probe and reconcile (landed in v0.4)

Both halves are in: `whyopen probe -target <ip> -ports <spec>` run from
anywhere, and `whyopen check -probe-from ssh://host`, which asks a second
machine to probe this host's global address on every TCP port something
here is listening on. `internal/probe` holds the connect probe, the
reconciliation and the ssh runner; the runner is an interface, so the
wiring is tested without an ssh server.

The probe is authoritative for TCP and UDP stays model-only, as this entry
asked. Three refinements the entry did not name, each because writing it
raised the question:

- A refused connection is not the same as no answer. A reset means the
  packet reached the host's TCP stack or a rule that rejects rather than
  drops, so `closed` and `filtered` are separate states and the verdict
  says which happened.
- A probe that errored (no route, a DNS failure) is ignored entirely
  rather than merged. Not finding out is not evidence, and treating it as
  any kind of answer would let a broken vantage point overrule the model.
- The probe answers about an address and a port, not about a socket, so
  when several sockets share a port the same answer lands on all of them
  and the reason says whyopen cannot tell which one answered. One
  disagreement is recorded per port rather than per socket.

Reality reaches the policy: reconciliation happens before the policy
check, so a port the probe found open is a violation if the policy does
not allow it, whatever the ruleset was read to mean. A probe that could
not run is a tool error rather than a quiet fall back to the model,
because a run that silently did not check reality looks exactly like one
that did.

The target and the port list end up in a command another machine's shell
runs, so the target must parse as an IP address and the ports are
rendered from numbers, checked before anything is run rather than quoted
and hoped for.

What is left: this is a TCP connect probe, so it needs a listener to
answer and says nothing about UDP. A host behind NAT is exactly the case
it was wanted for, and it handles it the same way as any other: the model
refuses to conclude, and the probe decides.

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

Released: `v0.1.0` was tagged and pushed on 2026-08-29 and the workflow
published both archives, both debs, both rpms and `checksums.txt`. Three
small gaps were found in review and deliberately deferred rather than
rushed into that tag; all three were closed before v0.2.0:

- `wrap_in_directory` is now set on the archives, so a `tar.gz` extracts
  into a named directory instead of into the current one. Checked by
  running a GoReleaser snapshot and listing the tarball, not by reading
  the config.
- The `version` subcommand now falls back to `debug.ReadBuildInfo`
  (`resolveVersion` in `cmd/whyopen/main.go`): a binary from `go install`
  reports the module version it was installed from, and one built in a
  checkout reports the VCS revision and commit time. Whatever the linker
  injected still wins, since a release build is told its own tag.
- The release workflow now runs gofmt, both vet passes and the unit suite
  before GoReleaser, so a tag that fails the unit tier no longer
  publishes. The integration tier still runs only on master, where it
  gates the commit a tag points at.

## Smaller items, roughly in value order

- ~~Read `NFTA_HOOK_DEV` so an ingress chain only affects its own
  device.~~ Done. whyopen issues one `NFT_MSG_GETCHAIN` dump of its own,
  in `internal/collect/chaindev.go`, and reads both the single-device
  attribute and the `NFTA_HOOK_DEVS` list a multi-device chain carries.
  It needed a wider read surface than decisions 0001 and 0005 allow, so
  it has its own record: `docs/decisions/0006-reading-chain-devices.md`,
  which also fences what that file may ever send. A failed read is not a
  failed ruleset read: the devices are unknown, the chain is treated as
  seeing everything, and the verdict is the blunt one whyopen gave
  before. The patch belongs upstream in `google/nftables`; when it lands
  there, `chaindev.go` and the exception should be deleted rather than
  kept as a second source of the same truth.

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

## After 1.0

Nothing here blocked 1.0, and each is here because closing it needs
evidence or a user rather than a decision.

- ~~**`expr.Range`.**~~ Done in v1.1, and the capture was worth doing:
  the guess in decision 0004 was wrong. `tcp dport 1024-2048` produces no
  range expression at all, it compiles to two ordered comparisons, so a
  decoder written from that guess would have closed the rare negated form
  and left the common one open. All three shapes resolve now, recorded in
  `docs/decisions/0011-ranges-and-interval-sets.md`. The interval reaching
  the top of the type's range, which that record deferred, was captured in
  v1.2 and resolves too: such an interval simply has no end element, and
  five captured set shapes settle that it never has to be told apart from
  the zero sentinel.
- ~~**`xt recent --remove`.**~~ Done in v1.1. Captured at 0x08, which is
  what the pattern of the other three predicted. Decision 0003's update
  records that the inference would have been right and that refusing it
  was still correct: a guess that happens to be right is not evidence, and
  there was no way to tell which kind it was without the capture.
- **The library patch belongs upstream.** `google/nftables` drops
  `NFTA_HOOK_DEV` when it reads a chain back, which is why
  `internal/collect/chaindev.go` exists. When that lands upstream, delete
  the file and the exception in decision 0006 rather than keeping a second
  source of the same truth.
- ~~**firewalld against the daemon.**~~ Done in v1.2, and it found
  something on the first run: a real firewalld emits `ct status dnat
  accept` in filter_INPUT and filter_FORWARD, which the hand-written
  ruleset never produced and which made every port on such a host unknown.
  A CI job now installs and starts the daemon, asserts that every native
  expression it emits decodes, and checks the verdicts against what
  `firewall-cmd` was told to open. One construct is a documented gap
  rather than a decoded one: firewalld's IPv6 reverse-path check
  (`fib saddr . mark . iif oif missing`) depends on the host's routing
  table, which whyopen does not collect, so IPv6 verdicts there are
  unknown. That gap is closed too, in v1.3: whyopen reads the routing
  table from /proc, and `docs/decisions/0012-fib-and-routes.md` records
  why it only ever concludes a route is present and never that one is
  missing.
- **A native expression whyopen cannot type keeps nothing.** Decision 0007
  closed this for xt payloads. There is no equivalent opaque blob behind a
  typed native expression, so the same fix does not apply, and what
  whyopen does not decode is recorded as `ExprUnknown` with the type name.
  Worth revisiting only if a real ruleset turns up where it matters.
