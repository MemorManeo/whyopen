# whyopen: design

Date: 2026-08-28
Status: approved, ready for implementation planning

## 1. Problem

On a Linux host running Docker behind UFW, no one can answer the question
"which ports are actually reachable from the internet right now, and why?"
without reasoning by hand across three separate systems: the set of listening
sockets, the nftables ruleset (into which both UFW and Docker write, with
different conventions and different hook priorities), and Docker's port
publishing plus DNAT.

The failure is not exotic. It is the default outcome:

- Docker writes its own nat and filter rules. A container published on
  `0.0.0.0` is reachable from the internet even when UFW is active, enabled,
  and shows a deny-by-default policy. UFW's `ufw-user-input` chain is never
  consulted for that traffic, because the packet is DNAT'd in
  `prerouting/nat` and then handled in `forward/filter`, not `input/filter`.
- A process that binds every interface (Express with no host argument binds
  `*`) is exposed regardless of what the service manager's environment
  suggests, because nothing enforces the intent.
- A `::` bind also accepts IPv4 when `net.ipv6.bindv6only=0`, which is the
  default, so a single socket has two different reachability answers.
- Stale allow rules survive the service they were written for, and Docker
  publishes survive the container that needed them.

On the author's own host, five containers sat published on `0.0.0.0` and were
internet-reachable for months while UFW was enabled; one of them, Postgres on
5432, collected roughly 940 brute-force attempts per day before it was found.

The state of the art for detecting this, per every tutorial and blog post on
the subject, is "run nmap from another machine and hope you notice". The state
of the art for fixing it is `chaifeng/ufw-docker`, a script that rewrites
rules. Nothing audits, and nothing explains.

## 2. Goals

1. Answer, for every listening socket on the host, whether a packet from the
   public internet can reach it, separately for IPv4 and IPv6.
2. For every answer, show the causal chain: the ordered list of nftables rules
   the packet traverses, so the operator learns why, not just what.
3. Be trustworthy enough to run on a production host: read-only, no daemon, no
   telemetry, no network egress unless explicitly asked.
4. Be a guardrail, not a one-off: a declarative policy file and a meaningful
   exit code, so it runs from cron and from CI after every compose change.
5. Never guess. An unparsed rule yields an explicit `unknown` verdict, not an
   optimistic one.

## 3. Non-goals

Out of scope for v1, deliberately:

- Fixing anything. No rule writing, no remediation subcommand. Read-only is
  the product's trust anchor.
- firewalld and iptables-legacy backends. Detect their presence and warn
  loudly that the verdict may be incomplete, rather than modelling them.
- Podman, Kubernetes, LXC. Detect and mark affected listeners `unknown`.
- Source zones other than the internet (LAN, VPN, container to container).
  The model is built around a source zone abstraction so these are additive,
  but v1 ships exactly one zone.
- Daemon mode, Prometheus exporter, web UI, TUI.
- Non-Linux platforms. `probe` is the only subcommand that runs elsewhere.

## 4. Users

Self-hosters and small teams running Docker on a single VPS or homelab box,
plus the security-conscious operator who wants a CI gate on exposure. The
first run must produce a useful answer in under 30 seconds with no
configuration.

## 5. Prior art

| tool | what it does | gap |
|---|---|---|
| `nmap` from outside | ground truth on reachability | no explanation, no local correlation, needs a second machine, no policy gate |
| `ss` / `netstat` | listening sockets | says nothing about reachability |
| `chaifeng/ufw-docker` | rewrites rules to make UFW govern Docker | changes state, does not report, does not verify |
| `docker-bench-security`, `lynis` | broad CIS-style checklists | do not correlate sockets, ruleset and Docker publishes into a per-port verdict |
| `nft list ruleset` | the raw truth | unreadable at the volume Docker generates |

The unoccupied position is a read-only correlator that produces a per-port
verdict with a causal explanation and a policy exit code.

## 6. Architecture

Four stages, strictly separated:

```
collect  ->  Facts (JSON)  ->  model  ->  Verdicts  ->  report
                                  ^
                          probe -> reconcile
```

The load-bearing decision: `collect` and `model` are joined only by a
serializable `Facts` document. `whyopen collect > facts.json` on the host,
`whyopen check --facts facts.json` anywhere.

Three consequences, all of which the project depends on:

1. The evaluator is a pure function, so it is table-testable against recorded
   real-world rulesets with no privileges and no Docker.
2. A bug report is one attached file that reproduces the verdict exactly.
3. A hardened host can be audited from a workstation.

### 6.1 collect (the only impure stage)

Sub-collectors, each independently testable and independently degradable:

- **sockets**: listening TCP and UDP endpoints via netlink `sock_diag`
  (`INET_DIAG`), giving family, bind address, port, socket inode and uid.
  Inode maps to pid via `/proc/*/fd`, pid maps to cgroup, cgroup maps to a
  systemd unit or a container id.
- **ruleset**: the full nftables ruleset across the `ip`, `ip6` and `inet`
  families, including base chain hook and priority, chain policy, and every
  rule's expressions in order. Both UFW and Docker reach the kernel through
  iptables-nft, so both appear here.
- **docker**: containers, published port mappings (host ip and port to
  container ip and port, per protocol), networks and their bridges, and
  whether userland-proxy is active. Read from the Docker API when the socket
  is reachable; inferred from DNAT rules plus veth and bridge topology when it
  is not.
- **host**: interfaces and addresses classified as public global unicast
  versus RFC1918, ULA, loopback or link-local; routes; and the sysctls that
  change the answer (`net.ipv4.ip_forward`,
  `net.ipv6.conf.all.forwarding`, `net.ipv6.bindv6only`).

`Facts` carries `schema_version`, a capture timestamp, the host identity, and
a list of collection warnings (for example "docker socket not readable,
publishes inferred from DNAT").

### 6.2 model (pure, zero I/O)

For each listener and each address family, the evaluator constructs a
synthetic packet:

```
saddr = an address outside every local subnet   (the internet zone)
daddr = a public global-unicast address of the external interface
dport = the listener's port
proto = tcp | udp
iif   = the external interface
ct state = new
```

It then walks the real netfilter hook order, recording every rule it hits:

1. `prerouting` / nat, ascending priority. Docker's DNAT lives here at
   priority `dstnat` (-100). A match rewrites daddr and dport, and the walk
   continues with the rewritten packet.
2. Routing decision on the possibly-rewritten daddr: local delivery or
   forwarding.
3. `input` / filter for local delivery. UFW's chains hang here.
4. `forward` / filter for forwarded traffic. `DOCKER-USER`,
   `DOCKER-ISOLATION-STAGE-*`, `DOCKER` and `ufw-user-forward` all hang here,
   in a priority order that is the single most misunderstood part of the
   system.

Semantics the evaluator must get right, because they are where hand-reasoning
fails:

- **Base chains at the same hook run in ascending priority order, and an
  `accept` in one base chain does not skip the others.** Only `drop` and
  `reject` terminate immediately. This differs from the iptables mental model
  most operators carry, and it is why "UFW says deny" and "the port is open"
  can both be true.
- Chain policy applies when a base chain runs to the end without a verdict.
- `jump` returns to the caller on fallthrough or `return`; `goto` does not.
- `ct state related,established accept` rules, which Docker emits liberally,
  do **not** match a fresh inbound SYN. Fixing ct state to `new` is what makes
  the synthetic packet honest.
- `fib daddr type local` (what `-m addrtype --dst-type LOCAL` compiles to)
  must be resolved against the collected address set.
- Masquerade rules in `postrouting` do not affect inbound reachability and are
  recorded but not scored.

Output per (listener, family):

```
Verdict = reachable | filtered | unknown
Path    = ordered []RuleHit, each with table, chain, hook, priority,
          rule handle, rendered rule text, and the match outcome
```

`unknown` is a first-class verdict, produced whenever the evaluator meets an
expression it does not resolve. A tool that silently guesses "filtered" on a
rule it did not understand is worse than no tool.

A separate finding class, cheap to produce and immediately useful: a **dead
publish**, meaning a DNAT rule pointing at a container address and port with
no listener behind it.

### 6.3 probe and reconcile (opt-in)

Two forms, both off by default:

- `whyopen check --probe-from ssh://user@host` opens an SSH connection and
  runs a per-port TCP connect test on the far side using only shell builtins,
  so nothing has to be installed there.
- `whyopen probe --target <ip> --ports <spec> --json` runs on any machine that
  already has the binary and emits results that
  `whyopen check --probe-results <file>` consumes.

Probe results are merged into the verdict set, with the probe authoritative
for TCP. UDP is never probed and stays model-only, labelled as such.

The reconciliation report is the highest-value output in the tool. "The model
said filtered, reality says open" is a live exposure the parser missed, and it
doubles as a self-generating bug funnel. Disagreements are printed as
diagnostics; policy evaluation runs on the merged verdicts.

### 6.4 report

Renderers over the same verdict set:

- Human table, grouped by verdict, worst first, with the owning unit or
  container per row.
- `--json`, a stable and versioned schema.
- `explain`, the full ordered rule path for one port.

## 7. CLI surface

```
whyopen check    [--facts F] [--policy P] [--probe-from URL]
                 [--probe-results F] [--json]
whyopen collect  [-o facts.json]
whyopen explain  <port>[/tcp|/udp] [--family ip|ip6] [--facts F]
whyopen probe    --target <host> --ports <spec> [--json]
whyopen policy   init [-o whyopen.yaml] [--facts F]
```

Exit codes:

| code | meaning |
|---|---|
| 0 | every verdict matches policy |
| 1 | policy violation: something reachable that policy does not allow |
| 2 | `unknown` verdicts present and `fail_on_unknown` is set |
| 3 | tool error (unreadable ruleset, missing privilege, bad arguments) |

## 8. Policy file

```yaml
version: 1
zones:
  internet:
    allow:
      - 22/tcp
      - 80/tcp
      - 443/tcp
fail_on_unknown: true
```

`whyopen policy init` writes this file from the host's current state, so
adoption is a single command followed by an edit. Anything reachable and not
listed is a violation. Anything listed and not reachable is reported as a
stale expectation, at info level, without failing.

## 9. Privilege and safety posture

- Requires root for the full picture: `sock_diag` for other users' sockets and
  netlink for the nftables ruleset. Without root, it reports what it can and
  names the exact missing privilege and its effect, rather than failing
  opaquely or silently under-reporting.
- No write path to nftables, iptables or Docker is linked into the binary.
- No telemetry, no auto-update, no network egress except an explicit
  `--probe-from`.
- `facts.json` contains host addresses, container names and the ruleset. The
  docs must say so plainly, since users will attach it to bug reports.

## 10. Testing strategy

The `collect` / `model` split exists to make this possible.

**Golden tests over recorded facts** (the bulk of the suite, pure, fast, no
privileges). Fixtures to record and check in:

1. Clean host, UFW default deny, no Docker.
2. Docker publish on `0.0.0.0` behind an active UFW (the canonical trap).
3. Docker publish on `127.0.0.1` (the correct configuration).
4. Host with `ufw-docker` rules applied.
5. `DOCKER-USER` deny rule present and effective.
6. IPv6 reachable while IPv4 is filtered (the dual-stack blind spot).
7. `::` bind with `bindv6only=0`, one socket and two verdicts.
8. Dead publish: DNAT with no listener behind it.
9. A ruleset containing an expression the evaluator cannot resolve, asserting
   `unknown` rather than a guess.

**Integration tests in CI**: build real network namespaces with veth pairs,
apply real rulesets, run the collector and the evaluator against them, and
assert verdicts against reality. GitHub Actions runners are VMs with root, so
nftables works directly.

**Dogfood**: the author's host, with its UFW plus Docker plus seven bridge
networks, is fixture zero and the first bug source.

## 11. Implementation notes

- Go. Single static binary, trivial cross-compile, the official Docker SDK is
  Go, and the netlink ecosystem is mature.
- `go.mod` declares a modern Go version and relies on the `toolchain`
  directive, so the box's Go 1.22.2 fetches the required toolchain
  automatically and no root-level toolchain upgrade is needed.
- Targets: linux/amd64 and linux/arm64. arm64 is not optional; a large share
  of the audience runs Raspberry Pi hardware.

### 11.1 Open question, resolved by spike before anything else is built

Whether to read the nftables ruleset over netlink (`google/nftables`, no
external binary, preserves the single-static-file promise) or by shelling out
to `nft -j list ruleset` (decodes everything the kernel reports, including
matches compiled from iptables-nft, but adds a runtime dependency).

There is genuine doubt that netlink decoding covers every expression Docker
emits. The author's host carries a real UFW plus Docker plus seven-bridge
ruleset. First implementation task: dump it both ways, diff the expression
coverage, and decide on the evidence. The `Facts` schema is designed so the
choice is confined to one collector and does not leak into the model.

## 12. Milestones

1. **Spike**: netlink versus `nft -j` expression coverage on a real ruleset.
   Output is a decision, not code that ships.
2. **Facts schema and collectors**: sockets, ruleset, docker, host. Produces
   `facts.json` on a real box.
3. **Evaluator**: hook traversal, verdicts, paths, driven by the golden
   fixtures. This is where the correctness lives.
4. **Report and explain**: human table and `--json`.
5. **Policy and exit codes**: `check` becomes a cron and CI guardrail.
6. **Probe and reconcile**: opt-in verification, disagreement diagnostics.
7. **Release**: GoReleaser, static amd64 and arm64 binaries, deb and rpm, a
   README whose first screenful is a real annotated verdict table.

## 13. Repository

- Location on this box: `~/files/privat/memormaneo-projects/whyopen/`, which
  matches the `argus` precedent (public, GitHub, published tool, deploys
  nowhere) and applies the MemorManeo git identity automatically via the
  `includeIf` rule in `~/.gitconfig`.
- Remote: `git@github-memormaneo:MemorManeo/whyopen.git`, mirrored to Gitea.
- Adds no systemd unit, no nginx site, no certificate and no port to the
  homelab inventory.
- License: Apache-2.0. The patent grant matters for a security tool that
  companies will run, which is the one respect in which it differs from
  `argus` (MIT).
