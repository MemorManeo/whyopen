# 0014: A forwarded port is an endpoint

Date: 2026-08-30
Status: accepted
Resolves: the blind spot `TestHandWrittenPortForwardIsVisible` found in
v1.6 and `docs/superpowers/plans/NEXT.md` recorded, where a port this host
forwards to another machine produced no output at all.

## Question

whyopen found ports in two places, and both describe this host: a
listening socket in `/proc/net`, and a Docker publish read through the
Docker API. A router or a VM host that forwards a port to a machine on its
LAN has neither. The integration test applied exactly that rule,

```
tcp dport 8080 dnat to 192.0.2.50:80
```

and whyopen reported **nothing** for 8080: not `unknown`, not a row,
silence. That is worse than a wrong verdict. Every other failure mode of
this tool says something a reader can chase; this one shows an empty table
to someone whose host is forwarding a port to a machine the table never
mentions, and an empty table reads as "nothing is exposed".

Closing it needs a third source of endpoints, and three decisions the
implementation cannot make on its own:

1. What such an endpoint is called. There is no process and no container
   on this host to name as its owner.
2. What `reachable` means for a port whose service lives on a machine
   whyopen cannot see.
3. Whether a rewrite with no port constraint means every port is
   forwarded.

## Decision

**Scan the ruleset for destination rewrites, and only for candidate
ports.** `internal/model/forwards.go` walks every base chain on the
prerouting hook, and the chains they jump to, looking for a native `nat`
expression of type dnat or an xt `DNAT` target. What it produces is not a
verdict: it is a port, which then goes through the same traversal every
socket and every publish goes through.

That asymmetry is the whole design. If the scan names a port whose rule
never actually matches, the traversal says so and the row reads `filtered`
with a reason. If the scan misses a port, the silence is back. So the scan
errs toward producing rows, and correctness lives in the traversal that
already existed, not in a second evaluator written to read rules
statically.

**The endpoint is named for its destination.** `Kind` is `forward`, beside
`socket` and `publish`, and the `OWNER` column reads `forwarded to
192.0.2.50:80`. The bind address is left empty: the rewrite applies
wherever its rule matches, and which of the host's addresses that is comes
out of the traversal rather than out of a guess made while scanning.

**`reachable` stops at the edge of the host, and says so.** The reason on
such a row ends with

> whyopen cannot see 192.0.2.50, so this says the packet is forwarded
> there, not that anything answers

which is the same honesty a Docker publish already gets, one step further
out: whyopen cannot see into another network namespace, and it certainly
cannot see another machine. `check --probe-from` is still what tells a
live forward from a dead one, and a probe's answer overrules this row the
way it overrules any other.

**A rewrite whyopen cannot reduce to ports becomes a warning, not a row.**
A rule with no port constraint forwards every port, and a rule matching a
range forwards more ports than a table should list. Neither can honestly
become one row, and inventing 65535 of them is not an answer either. They
are reported in the warnings block instead:

```
warnings (the table above is not the whole story):
  forwarded-ports: ip nat/prerouting rule 6 rewrites the destination to
  192.0.2.51 with no port constraint at all, so it forwards every port;
  whyopen reports one port per row and cannot list them
```

The rule is named by family, table, chain and handle, so it can be found
in the ruleset. What is refused here is exactly what is refused elsewhere:
a range (in either shape decision 0011 captured), an interval set, a map,
a concatenated key type, a set this document does not carry, a port
compared through a bitmask, and a protocol matched with anything but an
equality. Each becomes a sentence rather than a row, because the one thing
this must never do again is stay silent.

**A port that already has a row keeps it.** The scan's endpoints are
merged last, and dropped when a socket or a publish already reports that
protocol and port. Such an endpoint's own evaluation walks the same
prerouting hook and follows the same rewrite, so a second row would say
the same thing twice under a different name. Without this, every published
port on a Docker host would be reported twice, since a publish is a
destination rewrite too. The bind address is deliberately not part of that
test: a rewrite and a socket on one port are the same port to a reader,
whichever address either is bound to.

## Refused

**Modelling a rewrite the traversal cannot follow.** Source NAT and
masquerade live in postrouting, which whyopen does not walk, and a rewrite
in the output hook acts on traffic this host sent. Only prerouting is
scanned.

**Reading a port the rule did not name.** A rule that constrains no
protocol reports both tcp and udp, since a transport-header match applies
to whichever header arrives; that is the one place the scan deliberately
over-produces, and over-reporting an exposure is the direction this tool
errs in. Everything else it cannot read becomes a warning.

**Guessing what is behind the rewrite.** The row says a packet is
forwarded to an address. Whether a machine is there, whether it listens,
and what it runs are all outside what a firewall snapshot can answer.

## Consequences

- A forwarded port participates in everything a port participates in: the
  policy check treats it as reachable exposure and fails a run that does
  not allow it, `policy init` adopts it, `--json` carries it with
  `"kind": "forward"` and the `dnat` object, and `--explain` prints the
  rewrite rule.
- The warnings block now carries two kinds of warning, so its heading
  changed from "the snapshot is incomplete" to "the table above is not the
  whole story". The old heading described only what collection could not
  see.
- A rewrite whose target is one of this host's own addresses
  (`dnat to <self>:80`) is followed into the input hook like any other
  rewrite, and the row does not check whether anything listens on the
  rewritten port. It over-reports in the direction this tool always
  over-reports in, and the reason names the rewrite, so a reader can go
  look at the port it lands on.
- A rewrite whyopen cannot reduce to ports is a warning and nothing more:
  it does not change the exit code. A CI job reading only the exit code
  will not learn about a host that forwards every port. Whether that
  should fail a run is a policy question, left for whoever needs it.
- The scan runs twice per `check`: once inside `Evaluate`, for the
  endpoints, and once through `model.ForwardNotes`, for the warnings the
  command prints. It is pure and walks one hook, which is cheaper than
  threading a second return value through `Evaluate` and every caller of
  it.
