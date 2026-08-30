# whyopen

`whyopen` answers one question: what is actually reachable from the
internet on this Linux host, and which nftables rule decides that. Run it
and read the table.

```
$ sudo whyopen check
RESULT     PORT       FAMILY  OWNER                       BIND        WHY
reachable  80/tcp     IPv4    nginx.service               0.0.0.0     via 203.0.113.10: delivered locally, so the input hook decides
reachable  80/tcp     IPv6    nginx.service               ::          via 2001:db8::10: delivered locally, so the input hook decides
reachable  443/tcp    IPv4    nginx.service               0.0.0.0     via 203.0.113.10: delivered locally, so the input hook decides
reachable  443/tcp    IPv6    nginx.service               ::          via 2001:db8::10: delivered locally, so the input hook decides
unknown    22/tcp     IPv4    ssh.service                 0.0.0.0     rule 104966 in filter/ufw-user-input uses an expression whyopen cannot resolve
unknown    22/tcp     IPv6    ssh.service                 ::          rule 65113 in filter/ufw6-user-input uses an expression whyopen cannot resolve
filtered   4319/tcp   IPv4    node                        ::          fell through to the drop policy of filter/INPUT
filtered   5432/tcp   IPv4    postgresql@16-main.service  127.0.0.1   bound to 127.0.0.1, which does not match any host address the internet can reach
filtered   8888/tcp   IPv4    search-1                    127.0.0.1   bound to 127.0.0.1, which does not match any host address the internet can reach
```

That is a real run against an Ubuntu 24.04 host with UFW and Docker, 275
rules across 89 chains, with service and container names generalised. That
exact snapshot is committed as `testdata/facts/ufw-docker-host.json` and the
verdicts above are asserted by the test suite.

The two `unknown` rows on port 22 date the snapshot rather than describe
whyopen today. It was captured before whyopen decoded the `xt recent`
extension that `ufw limit ssh` uses, and that build discarded the payload
it could not read, so those two rules carry nothing to decode and whyopen
still declines to guess about them. A current run against a live UFW host
decodes them and resolves port 22, which the integration suite asserts
against a real kernel. Snapshots taken from v0.6.0 on keep the payload of
every xt extension, whether whyopen decoded it or not, so a later build
with a better decoder re-reads them from the document and says on stderr
how many it read differently. The verdicts above are as
collected, not edited to show what a fresh run would produce; only the owner
names are generalised, as noted above, and the table shows nine of the
thirty-nine rows.

- `RESULT` is `reachable` (a packet from the internet zone reaches this
  socket), `filtered` (some rule or bind address stops it), or `unknown`
  (whyopen cannot decide, see below). Rows are printed worst first:
  `reachable` on top, then `unknown`, then `filtered`, so an open port is the
  first thing on screen.
- `WHY` is one line; `whyopen check --explain PORT` prints the full ordered
  path of nftables rules that produced it, table by table, chain by chain,
  with an nft-like rendering of every rule that mattered.
- A Docker container published with `-p 127.0.0.1:5432:5432` shows up as
  `filtered` here because the bind address itself keeps it off the wire,
  before any nftables rule is even consulted.
- `reachable` on a published port means the rules do not stop the packet,
  not that something is listening inside the container. whyopen cannot see
  into another network namespace, so a publish with nothing behind it
  reads the same as a live one. `check --probe-from` is what tells the two
  apart.

## What `unknown` means

`unknown` is a first-class verdict, not an error. whyopen returns it whenever
it cannot follow the packet with confidence instead of guessing: an
unreadable iptables-nft compatibility match it does not decode, an nftables
expression it has no decoder for, a DNAT target that lands on no interface
subnet it knows about, a host with no global unicast address in that family,
a jump loop past its depth bound. An `unknown` result means "go look by
hand," not "this is fine."

Known gaps that produce `unknown` today:

- Native nftables expressions whyopen has no decoder for. UFW and Docker
  reach the kernel through iptables-nft, so their rules arrive as
  compatibility expressions; a hand-written nft ruleset or a firewalld
  host uses native ones instead, and only some of those decode. Both are
  exercised against a real kernel: CI runs a real firewalld, and a chain
  of the rules hardening guides tell people to write, asserting the
  verdicts rather than only that the expressions parsed. `ct state`
  and set lookups do, in every shape a captured firewalld-style ruleset
  produced: `ct state established,related accept` and `ct state
  { established, related } accept` compile to two different netlink shapes
  and both resolve, as do an anonymous set (`tcp dport { 22, 80 }`) and a
  named one (`tcp dport @allowed`). Ranges do too, in every shape a capture
  found them in: `tcp dport 1024-2048`, which the kernel compiles to two
  ordered comparisons rather than to a range expression at all, its
  negation, which is the form that does produce one, and a range inside a
  set, named or anonymous, including one reaching the top of the port
  range. What whyopen still refuses there is a set it will not read as a
  membership test at all: a map or verdict map, a concatenated key type, a
  set whose elements the facts document does not carry, or an element
  layout no capture has produced.
- A base chain on the **ingress** hook. It runs before prerouting, sees
  raw frames rather than the IP-level context whyopen evaluates in, and
  can drop a packet before any rule whyopen walks, so a port whose traffic
  arrives on one of that chain's devices reports `unknown`. The hook is
  per device and whyopen reads which devices, so a chain on another
  interface leaves your other ports alone. If it cannot read them, it
  falls back to treating the chain as seeing everything and says so in
  the reason. The egress hook is not treated this way: it acts on the
  reply, which this model does not follow, the same reason the output
  hook is never walked.
- The `xt recent` extension decodes the four `check_set` bit patterns
  captured from a live kernel, which covers every mode `iptables -m
  recent` can be written with. Any other value stays `unknown`: the
  decoder matches what was captured and does not extrapolate from it.

Forwarding is read per interface (`net.ipv4.conf.<if>.forwarding`) as well
as globally, because the kernel consults the device a packet arrived on:
a host that leaves `net.ipv4.ip_forward` at 0 and forwards on one
interface really does forward, and used to be reported as filtered. That
was the one known gap pointing the other way, reporting `filtered` where
the port may be open, and there is no other known gap in that direction.
If you find one, it is the most serious kind of bug this tool can have.

## Requirements

- Linux only, with an nftables ruleset. UFW and Docker's DNAT rules both go
  through nftables today and are covered. Rules written to the
  **iptables-legacy** backend are invisible to whyopen, which reads only
  nftables; it detects that the backend is in use (a non-empty
  `/proc/net/ip_tables_names` or `/proc/net/ip6_tables_names`, which only
  the legacy kernel modules create) and warns that every verdict may be
  incomplete. It does not claim rules exist there: that file lists tables
  that have been registered, which happens as soon as anything loads the
  module, and whyopen cannot tell from `/proc` which of them carry rules.
  firewalld's own zone configuration is not read, but the nftables ruleset
  its backend writes is, and CI runs whyopen against a real running
  firewalld: one job installs the daemon, asserts that every native
  expression it emits decodes, and checks that a port `firewall-cmd` was
  told to open reports `reachable` while one it was not reports
  `filtered`. That job is what found firewalld's `ct status dnat` and its
  reverse-path `fib` rule, neither of which a hand-written imitation had
  produced; both decode now, and the job fails if the daemon emits
  anything else whyopen cannot read.
- Must run as **root** (or at least with `CAP_NET_ADMIN`) to list the
  ruleset over netlink and to attribute every listening socket to a
  process. Run unprivileged and whyopen still lists every listener it can
  find, but it cannot read the ruleset, so it refuses to guess: every
  verdict comes back `unknown`, the reason and a `warnings` block both say
  why, and `check` exits 3 (a tool error, not a clean run) so cron and CI
  notice.
- **whyopen is read-only.** It never creates, changes, or deletes an
  nftables rule, a socket, or anything else on the host. It only reads.
  The single exception sends nothing to *this* host either: `whyopen
  probe` opens ordinary TCP connections to a target you name, and runs
  only when you ask for it by name (`probe`, or `check --probe-from`).
  It connects and closes; it changes nothing anywhere.

## Install

Download a release archive for your architecture (amd64 or arm64) from the
[releases page](https://github.com/MemorManeo/whyopen/releases), extract it,
and put `whyopen` on your `PATH`. Debian and Ubuntu users can instead grab
the `.deb` package; Fedora, RHEL and openSUSE users the `.rpm`. Both install
`whyopen` to `/usr/bin`.

If you have Go installed:

```
go install github.com/MemorManeo/whyopen/cmd/whyopen@latest
```

Either way, `whyopen` needs root (or `CAP_NET_ADMIN`) to read the nftables
ruleset; see Requirements above.

## Usage

```
whyopen collect [-o FILE]                      snapshot this host into a facts document
whyopen check [-facts FILE] [-explain PORT] [-policy FILE] [-json]
              [-probe-from ssh://HOST]
                                               report what is reachable, and why
whyopen policy init [-o FILE] [-facts FILE]    write a policy from what is reachable now
whyopen probe -target IP -ports SPEC [-json]   connect to a host and report what answers
whyopen version                                print the build version
```

`whyopen collect` writes a portable JSON snapshot (a "facts document") of
the host's addresses, listening sockets, nftables ruleset, and Docker
publishes. `whyopen check` evaluates that snapshot (or collects a fresh one
if `-facts` is not given) and prints the verdict table. Passing a facts
document to `check -facts` lets you evaluate a snapshot taken elsewhere,
or replay a bug report, without re-collecting.

`whyopen check -explain PORT` prints the full rule path for one port: every
base chain hit, in traversal order, with the handle and an nft-like
rendering of each rule.

### Checking the model against reality: `probe`

Everything else in whyopen concludes what the kernel would do with a
packet by reading rules. This finds out by sending one.

```
$ whyopen probe -target 203.0.113.10 -ports 22,80,443,3000
PORT      STATE     DETAIL
22/tcp    open
80/tcp    open
443/tcp   open
3000/tcp  filtered
```

`open` completed a handshake. `closed` was answered with a reset, so the
packet reached the host's TCP stack or a rule that rejects rather than
drops, which is not the same as no answer at all. `filtered` got no answer
before the timeout. `error` means whyopen could not find out (no route,
for instance) and is never read as evidence about the port.

Probing your own host from itself proves little, because the packet may
never leave the machine. The point is to probe from somewhere else:

```
whyopen check --probe-from ssh://vantage.example
```

That asks `vantage.example` to probe this host's global address, on every
TCP port something here is listening on, and folds the answers into the
verdict set. The probe is authoritative for TCP: it found out, the model
concluded. UDP is left model-only, because a TCP probe says nothing about
it and an unanswered UDP probe says almost nothing about anything. It
needs whyopen installed on that machine, and your ssh config decides the
key, the port and the rest.

The disagreements are the reason to run it:

```
probe from ssh://vantage.example: 1 port(s) where the model and reality disagree
PORT      FAMILY  MODELLED  PROBED  WHAT THAT MEANS
3000/tcp  IPv4    filtered  open    the port is open and whyopen read the ruleset as
                                    closing it, so the model is missing something
```

Each direction means something different, and the table says which. The
model saying `filtered` where the probe gets in means whyopen is missing
something: treat the port as open and the model as wrong. The model saying
`reachable` where nothing answers means something between the probe and
this host stops it, a provider firewall or a cloud security group, and
nothing on this host will show it. An `unknown` that a probe resolves is
not a disagreement at all: it is the case probing exists for.

Reality reaches the policy: a port the probe found open is a violation if
the policy does not allow it, whatever the ruleset was read to mean. A
probe that could not run at all is a tool error (exit 3), never a quiet
fall back to the model, because a run that silently did not check reality
looks exactly like one that did.

### `--json`

`whyopen check --json` writes the verdict set as a versioned document
instead of a table, so the tool composes with whatever reads it:

```
$ whyopen check --json | jq '.verdicts[] | select(.result=="reachable") | "\(.port)/\(.proto)"'
"80/tcp"
"443/tcp"
```

The document carries `schema_version`, the build that produced it, the
hostname, the zone, every verdict, any collection warnings, and the policy
result when `--policy` was given, so a reader gets the judgement along
with the verdicts rather than having to re-implement it. `schema_version`
is its own number, not the facts document's: one describes what was
collected, the other what was concluded.

The ordered rule path is the expensive half of the document, so it is
included only under `--explain PORT`, which narrows the document to that
port exactly as it narrows the text output. Each hit carries the table,
chain, hook, handle and an nft-like rendering of the rule. The exit code
is the same in either output mode.

### Guardrail: the policy file

`whyopen check --policy whyopen.yaml` turns the report into a pass or a
fail that cron and CI can act on. The file says which ports may be
reachable from the internet:

```yaml
version: 1
zones:
  internet:
    allow:
      - 22/tcp
      - 443/tcp
fail_on_unknown: true
```

| exit | meaning |
|---|---|
| 0 | every reachable port is allowed |
| 1 | a violation: something reachable the policy does not allow |
| 2 | `unknown` verdicts, and `fail_on_unknown` is set |
| 3 | tool error: unreadable ruleset, missing privilege, unreadable policy, bad arguments |

A run with both a violation and an unknown exits 1, because a violation
is something whyopen concluded and an unknown is something it could not.
An entry carries no address family, so `443/tcp` allows the port over
IPv4 and IPv6 alike, and it is per protocol: allowing `22/tcp` says
nothing about `22/udp`. Anything allowed but not reachable is reported as
a stale expectation and never fails the run, since the host is not less
safe than the policy asked for.

There is no implicit discovery. Without `--policy` no policy is consulted
and `check` behaves exactly as it did before, and whyopen never picks up
a file from the working directory: the file that decides whether your run
passes should not depend on where you were standing. Anything in it
whyopen does not understand, an unknown key, another zone name, a port
range, a version other than 1, is an error that exits 3 rather than a
line quietly ignored into a false green.

`whyopen policy init` writes the file from what is reachable right now,
so adopting it is one command and an edit. It prints to stdout, takes
`-o FILE` to write one, and refuses to overwrite an existing file,
because a policy carries edits that a facts document does not. It never
seeds a port whyopen could not resolve into the allow list, and names
those in a comment instead: an allow list is for ports you decided to
open, not for ports nobody could account for. The file it generates sets
`fail_on_unknown: true`, so on a host with unresolved ports the next
`check --policy` exits 2. That is deliberate. A guardrail that ignores
what it cannot see is a false green.

## Compatibility

1.0 means these are promises, and breaking one takes a major version.

**The command line.** The subcommands, their flags, and above all the exit
codes: 0 clean, 1 a policy violation, 2 unknown verdicts with
`fail_on_unknown` set, 3 a tool error. Anything scripted against those
keeps working.

**The facts document.** Its `schema_version` is 1. It moves only when a
reader needs new code to read a document safely: a field removed, renamed,
or changed in meaning. Adding an optional field never moves it, so a
reader must treat a field it does not find as "the collecting build did
not record this", never as a fact about the host. whyopen reads every
version up to its own and refuses a newer one. The rule and its reasoning
are in
[decision 0010](docs/decisions/0010-facts-schema-versioning.md).

**The verdict document** written by `check --json` carries its own
`schema_version`, on the same rule. It is a separate number from the facts
document's: one describes what was collected, the other what was
concluded.

**The policy file** at `version: 1`, including which shapes are refused. A
policy that whyopen accepts today it will accept at 1.x.

What is deliberately **not** promised:

- **The reason strings.** They are prose for a human at 2am and they get
  reworded. Match on `result`, never on `reason`.
- **The table layout.** Use `--json` if something other than a person is
  reading it.
- **The Go packages.** Everything is under `internal/` on purpose.
- **That a given port keeps its verdict.** A better decoder turns an
  `unknown` into an answer, and that is the tool improving rather than a
  contract breaking. `unknown` means "whyopen could not tell", not "this
  port is special", and nothing should be pinned to it.

### Redact before you share

A facts document is a full inventory of the host: its hostname, every
network interface and IP address (including private ranges), every
listening socket with its owning process and systemd unit, and every
Docker container's name and published ports. Treat it like you would a
`nft list ruleset` dump or a `netstat` output: **redact it before attaching
it to a bug report** or pasting it anywhere outside your own infrastructure.

## Tests

`go test ./...` runs the unit suite and needs no privileges.

There is a second, root-requiring tier under `test/integration/`, behind
the `integration` build tag, which exercises whyopen against a real kernel
in throwaway network namespaces and, in two tests, against a real Docker
daemon. It mutates the host it runs on. Read
[test/integration/README.md](test/integration/README.md) before running
it. Every correctness claim in this README that could be checked against a
kernel is checked by that tier, and CI fails if it skips rather than runs.

## Why it decides what it decides

[`docs/decisions/`](docs/decisions/) is the record: what was chosen, what
was rejected, and what evidence settled it. Several of them exist because
reading the kernel disagreed with reading the documentation, which is why
the byte layouts in this tool were captured from a live kernel rather than
taken from a header file.

The original design is
`docs/superpowers/specs/2026-08-28-whyopen-design.md`. It is kept as the
origin rather than as current truth: where the decisions above disagree
with it, they are what shipped.
