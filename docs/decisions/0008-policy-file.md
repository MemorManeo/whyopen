# 0008: The policy file, and what a failing run means

Date: 2026-08-30
Status: accepted
Recorded after the fact: the decisions below were taken and shipped in
v0.3.0. They lived only in commit messages and in
`docs/superpowers/plans/NEXT.md`, which is a queue rather than a record,
and this file is written so 1.0 does not freeze a user-facing contract
whose reasoning is not written down anywhere.

## Question

`whyopen check` reported. Exit codes 1 and 2 were reserved in the original
design for a policy that did not exist yet, so every run exited 0 or 3, and
the tool could not be a guardrail: nothing in a cron job or a CI pipeline
could tell "the ports I expect" from "a port opened last week".

Section 8 of `docs/superpowers/specs/2026-08-28-whyopen-design.md` drew the
file. What it did not settle: what parses it, where it is found, what a
violation is, and which of two bad outcomes a run reports when it has both.

## Decisions

**The format is YAML, parsed by `github.com/goccy/go-yaml`.** A policy file
is a document people annotate, and JSON cannot carry a comment saying why
a port is open, which is the single most useful thing such a file records.
`gopkg.in/yaml.v3` is the obvious choice and was rejected on a fact: its
repository is archived and v3.0.1 (May 2022) is the last release it will
ever have, so a parser bug found later would be whyopen's to vendor around.
goccy is current, and its `go.mod` declares no dependencies of its own, so
the module graph grows by exactly one node. This is the first dependency
whyopen has taken that is not the netlink stack.

**Parsing is strict, and every refusal exits 3.** An unknown top-level key,
an unknown zone name, a `version` other than 1, an entry without a
protocol, a port range, a protocol whyopen does not model: all errors. A
policy decides whether a run passes, so a line whyopen does not understand
must stop the run rather than be ignored into a false green. The same
reasoning makes an unreadable policy file exit 3 rather than fall back to
reporting: exiting 0 there would silently stop enforcing the moment
someone fat-fingers the file.

**There is no implicit discovery.** Only `--policy PATH`. A root-run
security tool that picks up a config from the working directory is a
footgun: the file deciding whether your run passes should not depend on
where you were standing. Without the flag, `check` behaves exactly as it
did before the policy existed.

**An allow entry is per protocol and covers both address families.**
`443/tcp` allows the port over IPv4 and IPv6; allowing `22/tcp` says
nothing about `22/udp`, because reading it as though it did would hide an
open port. Family-specific entries were not invented, on this project's
standing rule against inventing a surface before someone needs it.

**A violation outranks an unknown.** A run with both exits 1. A violation
is something whyopen concluded; an unknown is something it could not, and
the concluded finding is the one worth acting on. An unreadable ruleset
still outranks both at exit 3, because it makes every other conclusion
void.

**A stale expectation never fails a run.** A port allowed but not
reachable is reported at info level: the host is not less safe than the
policy asked for. It is not reported as stale when the port's verdict is
`unknown`, because an expectation cannot be called dead on the strength of
a verdict that says whyopen could not tell.

**`policy init` writes what is reachable and nothing else.** It never
seeds a port whyopen could not resolve into the allow list, because that
would record "allow whatever I could not verify" in the file that decides
whether later runs pass; it names those in a comment instead. It sets
`fail_on_unknown: true`, which means that on a host with unresolved ports
the very next `check --policy` exits 2. That is deliberate and it is the
part of this record most likely to be questioned: a guardrail that ignores
what it cannot see is a false green, and the generated comment names the
ports so the failure is not a surprise. It refuses to overwrite an
existing file, unlike `collect -o`, because a facts document is
disposable and regenerable while a policy carries edits a human made.

**Evaluation is pure and lives in its own package.** `internal/policy`
takes a verdict set and a policy and returns a result; it imports the
stdlib, `internal/model` and the YAML parser, and nothing imports it but
`cmd` and `internal/report`. `internal/model` gained nothing at all: what
the kernel does and what the operator wanted stay in separate packages,
which is the same separation that makes an `unknown` verdict trustworthy.
It needs no root and no kernel to test.

## Consequence

`check --policy` is a guardrail with a documented exit code per outcome,
and `whyopen policy init` makes adopting one a command and an edit. The
allow list has no address families, no port ranges, and one zone, because
`model.InternetZone()` is the only zone whyopen models. Each of those is a
refusal to invent a surface, and each is a thing 1.0 will have to keep or
extend compatibly.
