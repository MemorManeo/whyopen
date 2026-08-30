# 0003: `xt recent` match payload layout

Date: 2026-08-29
Status: accepted
Resolves: the last `unknown` on a stock UFW host (`ufw limit ssh` emits `xt
recent` matches on port 22), tracked in `.superpowers/sdd/2026-08-29-whyopen-v0.1/`

## Question

`ufw limit ssh` compiles to two `iptables -m recent` rules protecting port
22, and whyopen decodes them as `xt.Unknown` today, so the port an operator
cares about most reports `unknown`. Decoding them means knowing the byte
layout `xt_recent` stores its match info in. Per decision 0001, that layout
is captured from a live kernel, not recalled from a header file: 0001 already
caught a case where the byte-accurate netlink reading differed from what the
`nft` text renderer implied, and there is no reason to trust memory over
bytes here either.

## Evidence

Captured in CI (run `33248241755`, job `integration`, `capture_test.go:41`)
on a GitHub Actions `ubuntu-24.04` hosted runner, `iptables 1.8.10-3ubuntu2`,
`nftables 1.0.9-1ubuntu0.1` (kernel version not printed by the job). Three
rules were created in a namespace, the two variants `ufw limit ssh` emits
plus a third for coverage, and the raw `xt.Unknown` bytes were read back
over netlink, bypassing the collector, which discards exactly this payload:

```
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --set --name SSH
recent[0] rev=1 len=232
hex=0000000000000000020053534800554c54000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff
    00000000

iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW \
  -m recent --update --seconds 30 --hitcount 6 --name SSH -j DROP
recent[1] rev=1 len=232
hex=1e00000006000000040053534800554c54000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff
    00000000

iptables -A INPUT -p tcp --dport 23 -m recent --rcheck --seconds 60 --name OTHER
recent[2] rev=1 len=232
hex=3c0000000000000001004f544845520054000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    0000000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffff
    00000000

(Line-wrapped for readability here; each is a single 464-character hex
string in the CI log, i.e. 232 bytes, all three at revision 1.)

### Derived offsets

All three payloads are 232 bytes, revision 1. Reading byte-for-byte:

| offset | field | width | evidence |
|---|---|---|---|
| 0-3 | `seconds` (`__u32`, LE) | 4 | `1e000000`=30 for `--seconds 30`, `3c000000`=60 for `--seconds 60`, `0` for `--set`, which takes no `--seconds` |
| 4-7 | `hit_count` (`__u32`, LE) | 4 | `06000000`=6 only on the `--hitcount 6` rule, `0` on the other two |
| 8 | `check_set` (`__u8`) | 1 | `0x02` for `--set`, `0x04` for `--update`, `0x01` for `--rcheck`; a clean bit-per-mode pattern (`1<<0`, `1<<1`, `1<<2`), consistent with the well-known `CHECK`/`SET`/`UPDATE` flags. `--remove` (`1<<3` by the same pattern) was not captured, so that bit value is not confirmed by this evidence, only inferred from the pattern the other three follow |
| 9 | `invert` (label inferred) | 1 | `0x00` in all three; no rule used `!`, so neither the flag's "set" value nor the field's identity is evidenced here; see note below |
| 10-209 | `name[200]` | 200 | see the `DEFAULT` overwrite below |
| 210 | `side` (source vs. dest) | 1 | inferred, see note below |
| 211 | padding | 1 | inferred, see note below |
| 212-227 | mask (`union nf_inet_addr`) | 16 | `ff` repeated 16 times in all three; the revision-1 addition, default all-ones when `--mask` is not given |
| 228-231 | trailing padding | 4 | `00000000` in all three; brings the struct to a multiple of 8 bytes, consistent with the kernel's `XT_ALIGN` rounding of the enclosing `xt_entry_match` entry |

**The `name` field's start and width, confirmed by a useful accident.**
iptables pre-fills `info->name` with the placeholder `"DEFAULT\0"` (8 bytes)
before the `--name` option overwrites it, and the overwrite does not clear
the rest of the 200-byte buffer, only the bytes the new name plus its null
terminator occupy. `--name SSH` writes 4 bytes (`S`,`S`,`H`,`\0`) over the
first 4 bytes of `DEFAULT\0`, leaving the remaining 4 bytes of the
placeholder, `U`,`L`,`T`,`\0`, untouched. Bytes 10-17 of payload 0 and 1 are
exactly `53 53 48 00 55 4c 54 00`, i.e. `SSH\0` followed by `ULT\0`, the tail
of `DEFAULT`. `--name OTHER` writes 6 bytes (`O`,`T`,`H`,`E`,`R`,`\0`),
leaving byte 6 of the placeholder, `T`, and byte 7, the already-zero
terminator; bytes 10-17 of payload 2 are `4f 54 48 45 52 00 54 00`, i.e.
`OTHER\0` followed by `T\0`. Both are consistent only with `name` starting
at absolute offset 10, and pin that offset exactly rather than approximately.

**`side` and the padding byte before the mask are inferred, not directly
observed.** None of the three captured rules used `--rdest`, so the `side`
byte is `0x00` (source) in all three, indistinguishable by value from
padding. Its position at offset 210, with one padding byte at offset 211
before the 16-byte mask begins at the next 4-byte-aligned offset (212), is
inferred by combining the observed total length (232), the known
`XT_RECENT_NAME_LEN` of 200, and standard struct alignment for a
4-byte-aligned `union nf_inet_addr`: `10 (header) + 200 (name) + 1 (side) +
1 (pad) + 16 (mask) + 4 (trailing pad) = 232`. An alternative reading treats
the byte at offset 210 as the 201st byte of `name` rather than a separate
`side` field; that reading still needs the same single padding byte at
offset 211 to reach the mask's 4-byte-aligned start, so it totals the same
232 bytes and puts the mask at the same observed offset, 212. What differs
between the two readings is only the label on the byte at offset 210, not
the byte count or the mask's position, and nothing here depends on choosing
between them, since neither the test data nor the evaluator rule below
reads that byte.

**Offset 9's identity is recalled from a header, not observed.** All three
payloads carry `0x00` at offset 9, so the capture establishes only that the
byte is zero for rules written without `!`. The label `invert`, and with it
the claim that a non-zero value there negates the match, comes from the
`xt_recent` uapi header, which is the one source this record's own premise
says not to trust; nothing in these bytes distinguishes that field from
padding. The decoder reads offset 9 as a boolean and the evaluator flips
the rule's outcome when it is set, so the semantic rule below rests on that
recalled identity rather than on this evidence. Before a verdict is allowed
to turn on it, capture a `! --update` variant and confirm the byte, exactly
as the `side` note above asks for `--rdest`.

## Decision

Decode `xt recent` matches at revision 1, length 232, using the offsets
above: `seconds` at 0, `hit_count` at 4, `check_set` at 8, `invert` at 9,
`name` at 10 (200 bytes, NUL-terminated), and the 16-byte mask at 212-227.
Any other revision or length is not covered by this capture and must decode
to `unknown` rather than guess.

**Semantic rule.** whyopen's synthetic packet always represents a first
connection from a source the recent list has never seen. That makes each
mode decidable without knowing any list state:

- `--set` (`check_set` `0x02`): the rule records the source and matches, on
  this or any packet.
- `--rcheck` (`0x01`) and `--update` (`0x04`): neither can match an empty
  list, so neither matches a never-seen source.
- `--remove`: has nothing to remove, so it does not match either. Its
  `check_set` byte was never captured, so in practice a `--remove` rule
  never reaches this test; it stops at the decoder, below.
- `invert` (offset 9), when set, flips whichever of the above the rule
  would otherwise produce. This step rests on the recalled field identity
  noted above, not on the captured bytes.

**Only the three captured bit patterns decode; everything else stays
undecoded.** A `check_set` byte that is not exactly `0x02`, `0x04` or
`0x01` leaves the match undecoded, and an undecoded match makes the port it
guards report `unknown`. The alternative reading, treating `check_set` as a
bitmask and resolving any uncaptured value by whether bit `0x02` happens to
be set in it, was considered and rejected. It would decide the outcome of
byte patterns this capture never observed, on the strength of a flag layout
recalled from a header rather than read off the wire, which is what
decision 0001 and whyopen's never-guess constraint forbid. Reporting
`unknown` for a rule shape whyopen has not seen is the correct answer here,
not a limitation to engineer around.

Two places enforce this, and a future implementer should keep both:
`recentModeName` in `internal/collect/nftconv.go` exact-matches the three
bytes and returns undecoded otherwise, and the `recent` case in
`internal/model/match.go` enumerates the five mode names and returns the
unresolved triple for anything else, so a facts document written by a later
version cannot resolve a mode this build does not model.

The `invert` byte is the one place the decoder does generalise: it reads
any non-zero value at offset 9 as inverted, though only `0x00` was ever
captured.

## Consequences

- Task 5's decoder and its fixtures are written against these three exact
  byte strings, not a recalled `struct xt_recent_mtinfo` definition.
- The `side` byte's offset is inferred rather than directly evidenced; if a
  future task needs to read `side` (for example to support `--rdest`), it
  should capture that variant rather than trust the inference here.
- `REMOVE`'s `check_set` bit value was never captured, so whyopen does not
  decode a `--remove` rule at all and reports `unknown` for the port such a
  rule guards. Inferring the bit from the pattern the other three follow
  was rejected (see the semantic rule above). Supporting `--remove` needs a
  fresh capture, not an inference.
- This is one kernel, one iptables version, one revision. A different
  kernel or a `--mask` argument narrower than all-ones is out of scope for
  this record.

## Update (v1.1): --remove captured

The fourth `check_set` bit was captured in CI (run `33318460615`, job
`integration`, `TestCaptureRecentRemove`) from two rules,
`iptables -m recent --remove --name SSH` and the same with `--name OTHER`,
so the mode bits could be told apart from the name bytes:

```
0000000000000000 0800 53534800554c54... (SSH)
0000000000000000 0800 4f544845520054... (OTHER)
```

`--remove` is `0x08`, at the same offset and in the same layout as the
other three, and the payload carries neither seconds nor hit count, which
is what `--remove` takes on the command line.

That is exactly the value this record declined to assume, and the outcome
is worth stating plainly rather than quietly: the inference would have
been right. It was still right to refuse it. The cost of refusing was one
CI run and an `unknown` verdict on a rule shape nobody had reported; the
cost of guessing wrong would have been a confident verdict on a rule
whyopen had never seen, which is the failure this whole project is built
to avoid. A guess that happens to be correct is not evidence, and there
was no way to know which kind it was without the capture.

whyopen decodes all four modes as of v1.1. The evaluator already modelled
`remove` (on whyopen's synthetic first-connection packet the list is
empty, so there is nothing to remove and the match cannot hit), so nothing
in the model changed.