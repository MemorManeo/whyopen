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
extension that `ufw limit ssh` uses, and a facts document preserves what the
collector understood when it ran, so those two rules still carry no decoded
payload and whyopen still declines to guess about them. A current run
against a live UFW host decodes them and resolves port 22, which the
integration suite asserts against a real kernel. The verdicts above are as
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

- Native nftables expressions whyopen has no decoder for. It decodes the
  shapes UFW and Docker emit, which reach the kernel through iptables-nft;
  a hand-written nft ruleset or a firewalld host uses native ones instead.
  Native `ct state`, anonymous set lookups (`tcp dport { 22, 80 }`) and
  ranges are all undecoded today, so on such a host a rule as ordinary as
  `ct state established,related accept` makes every port report `unknown`.

One known gap points the other way, reporting `filtered` where the port may
be open: whyopen reads only the global forwarding toggles
(`net.ipv4.ip_forward`, `net.ipv6.conf.all.forwarding`), so a host that
leaves those off but enables forwarding on one interface
(`net.ipv4.conf.<if>.forwarding=1`) is reported as not forwarding at all.

## Requirements

- Linux only, with an nftables ruleset. UFW and Docker's DNAT rules both go
  through nftables today and are covered. Rules written to the
  **iptables-legacy** backend are invisible to whyopen, which reads only
  nftables; it detects their presence (a non-empty `/proc/net/ip_tables_names`
  or `/proc/net/ip6_tables_names`, which only the legacy kernel modules
  create) and prints a warning saying every verdict may be incomplete.
  firewalld is not modelled either.
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
ruleset; see Requirements below.

## Usage

```
whyopen collect [-o FILE]                     snapshot this host into a facts document
whyopen check [-facts FILE] [-explain PORT]    report what is reachable, and why
whyopen version                               print the build version
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
