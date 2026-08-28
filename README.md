whyopen

`whyopen` answers one question: what is actually reachable from the
internet on this Linux host, and which nftables rule decides that. Run it
and read the table.

```
$ sudo whyopen check
RESULT     PORT       FAMILY  OWNER                BIND       WHY
reachable  22/tcp     IPv4    ssh.service          0.0.0.0    via 203.0.113.10: delivered locally, so the input hook decides
reachable  80/tcp     IPv4    -                    0.0.0.0    via 203.0.113.10: delivered locally, so the input hook decides
reachable  443/tcp    IPv4    -                    0.0.0.0    via 203.0.113.10: delivered locally, so the input hook decides
filtered   5432/tcp   IPv4    my-postgres          127.0.0.1  bound to 127.0.0.1, which does not match any host address the internet can reach
filtered   6379/tcp   IPv4    my-redis             127.0.0.1  bound to 127.0.0.1, which does not match any host address the internet can reach
unknown    9000/tcp   IPv6    my-app               ::         DNAT target is not on any known interface subnet, so the forward path cannot be resolved
```

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
unreadable iptables-nft compatibility match it does not decode, a DNAT
target that lands on no interface subnet it knows about, a host with no
global unicast address in that family, a jump loop past its depth bound. An
`unknown` result means "go look by hand," not "this is fine."

## Requirements

- Linux only, with an nftables ruleset (`iptables`-only hosts using the
  legacy backend are not read; UFW and Docker's DNAT rules both go through
  nftables today and are covered).
- Must run as **root** (or at least with `CAP_NET_ADMIN`) to list the
  ruleset over netlink and to attribute every listening socket to a
  process. Run unprivileged and whyopen still lists every listener it can
  find, but it cannot read the ruleset, so it refuses to guess: every
  verdict comes back `unknown`, the reason and a `warnings` block both say
  why, and `check` exits 3 (a tool error, not a clean run) so cron and CI
  notice.
- **whyopen is read-only.** It never creates, changes, or deletes an
  nftables rule, a socket, or anything else on the host. It only reads.

## Usage

```
whyopen collect [-o FILE]                     snapshot this host into a facts document
whyopen check [-facts FILE] [-explain PORT]    report what is reachable, and why
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

## Design

Design: docs/superpowers/specs/2026-08-28-whyopen-design.md
