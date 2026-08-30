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
against a real kernel. Snapshots taken from v0.4.0 on keep the payload of
every extension whyopen cannot type, so a later build with a better
decoder resolves them when it reads the document, and says on stderr how
many it re-decoded. The verdicts above are as
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
  host uses native ones instead, and only some of those decode. `ct state`
  and set lookups do, in every shape a captured firewalld-style ruleset
  produced: `ct state established,related accept` and `ct state
  { established, related } accept` compile to two different netlink shapes
  and both resolve, as do an anonymous set (`tcp dport { 22, 80 }`) and a
  named one (`tcp dport @allowed`). What still reports `unknown` there is a
  numeric range (`tcp dport 1024-2048`) or an interval-flagged set,
  undecoded because no captured ruleset has yet shown one; and,
  deliberately, a set whyopen will not read as a flat membership test: a
  map or verdict map, a concatenated key type, or a set whose elements the
  facts document does not carry.
- The `xt recent` extension decodes only the three `check_set` bit
  patterns captured from a live kernel, which is what `ufw limit ssh`
  emits. A `--remove` rule was never captured, so it still reports
  `unknown` rather than being guessed at from the pattern the other three
  follow.

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
  nftables; it detects their presence (a non-empty `/proc/net/ip_tables_names`
  or `/proc/net/ip6_tables_names`, which only the legacy kernel modules
  create) and prints a warning saying every verdict may be incomplete.
  firewalld's own zone configuration is not read, but the nftables ruleset
  its backend writes is: the expressions such a ruleset emits were
  captured and are decoded (see
  [decision 0004](docs/decisions/0004-firewalld-expressions.md)), though
  whyopen has been tested against a firewalld-shaped ruleset applied by
  hand, not against the daemon itself.
- Must run as **root** (or at least with `CAP_NET_ADMIN`) to list the
  ruleset over netlink and to attribute every listening socket to a
  process. Run unprivileged and whyopen still lists every listener it can
  find, but it cannot read the ruleset, so it refuses to guess: every
  verdict comes back `unknown`, the reason and a `warnings` block both say
  why, and `check` exits 3 (a tool error, not a clean run) so cron and CI
  notice.
- **whyopen is read-only.** It never creates, changes, or deletes an
  nftables rule, a socket, or anything else on the host. It only reads.

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
                                               report what is reachable, and why
whyopen policy init [-o FILE] [-facts FILE]    write a policy from what is reachable now
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
in throwaway network namespaces and, in one test, against a real Docker
daemon. It mutates the host it runs on. Read
[test/integration/README.md](test/integration/README.md) before running
it.

## Design

Design: docs/superpowers/specs/2026-08-28-whyopen-design.md
