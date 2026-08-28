# 0001: Read the nftables ruleset over netlink, not through `nft`

Date: 2026-08-28
Status: accepted
Resolves: the open question in `docs/superpowers/specs/2026-08-28-whyopen-design.md` section 11.1

## Question

Read the ruleset over netlink with `github.com/google/nftables` (no external
binary, preserves the single-static-file promise), or shell out to
`nft -j list ruleset` (assumed to decode more)?

## Evidence

Measured against a real host: Ubuntu 24.04, nftables 1.0.9, iptables 1.8.10
(nf_tables backend), UFW 0.36.2, Docker 29.1.3 with seven bridge networks.
5 tables, 89 chains, 276 rules.

**`nft -j` loses the data the tool exists to report.** 157 of the ruleset's
expressions are xtables compatibility shims, because both UFW and Docker
reach the kernel through iptables-nft. For every one of them, `nft -j` emits
only a name:

```json
{"xt": {"name": "DNAT", "type": "target"}}
```

The DNAT destination address and port are absent. That is the single most
important fact in the model: it is what turns an input-path question into a
forward-path question, and it is the whole mechanism behind a container
published on `0.0.0.0` being reachable while UFW looks correct. The `nft`
*text* renderer does print it (`dnat to 172.20.0.2:2222`), so the only way to
reach it through the binary is to parse human-readable output.

**Netlink decodes it, already typed.** `google/nftables` ships an `xt`
subpackage that decodes extension payloads into Go structs. The same rule
over netlink:

```
&expr.Target{Name:"DNAT", Rev:0x2, Info:&xt.NatRange2{NatRange:xt.NatRange{
    Flags:0x3, MinIP:172.20.0.2, MaxIP:172.20.0.2,
    MinPort:0x8ae, MaxPort:0x8ae}}}
```

`0x8ae` is 2222, matching the text renderer exactly. No hand-written struct
decoding is required.

Coverage of every xt extension present on the reference host:

| xt extension | count | decoded as | needed by the model |
|---|---|---|---|
| `target:DNAT` | 7 | `xt.NatRange2` | yes, destination rewrite |
| `match:conntrack` | 27 | `xt.ConntrackMtinfo3` | yes, does the rule match a fresh SYN |
| `match:addrtype` | 8 | `xt.AddrTypeV1` | yes, `--dst-type LOCAL` |
| `target:MASQUERADE` | 7 | `xt.NatIPv4MultiRangeCompat` | no, postrouting is not scored |
| `target:REJECT` | 9 | `xt.Unknown` | name only, terminal verdict |
| `target:LOG` | 10 | `xt.Unknown` | name only, non-terminal |
| `match:icmp` / `icmp6` | 60 | `xt.Unknown` | name only, cannot match TCP or UDP |
| `match:hl` | 22 | `xt.Unknown` | name only, conservative |
| `match:rt` | 3 | `xt.Unknown` | name only, conservative |
| `match:recent` | 4 | `xt.Unknown` | name only, conservative |

Every extension whose payload changes a verdict is typed. Every extension
that falls back to `xt.Unknown` is resolvable from its name alone, either
because it cannot match a TCP or UDP packet, or because it is a terminal
verdict, or because the model marks it conservatively.

Native expression coverage on the same ruleset is likewise complete:
`Cmp` 328, `Counter` 276, `Verdict` 241, `Payload` 172, `Meta` 156,
`Bitwise` 16, `Limit` 13. Nine expression kinds in total, all decoded.

## Decision

Read the ruleset over netlink with `github.com/google/nftables`, including
its `xt` subpackage. Do not depend on the `nft` binary.

The collector converts netlink types into whyopen's own serializable
expression union at capture time, so `internal/model` never imports
`google/nftables` and stays a pure function of `Facts`.

## Consequences

- No runtime dependency beyond the kernel. The single static binary promise
  holds.
- Extensions that decode to `xt.Unknown` and are not on the name-resolvable
  list above must produce the `unknown` verdict, never a guess.
- The reference host's own ruleset is fixture zero, but it currently has
  every Docker publish bound to `127.0.0.1`, so the canonical
  publish-on-`0.0.0.0` fixture has to be synthesised in a network namespace
  rather than captured.
