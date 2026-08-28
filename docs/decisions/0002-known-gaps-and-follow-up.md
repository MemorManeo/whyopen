# 0002: Known gaps carried out of the core plan

Date: 2026-08-28
Status: accepted
Context: recorded at the end of the core implementation plan so that findings
raised during review survive the scratch workspace they were found in.

Everything here was found by review or by running the tool against a real
UFW plus Docker host. None of it is speculative. Each item says why it was
not fixed in the core plan.

## Correctness gaps that produce `unknown` today

These are honest, not silent: the verdict says `unknown` and the reason names
the rule. They are listed because each one is a resolvable case that whyopen
currently declines to resolve.

- **`xt recent` is not decoded.** UFW's `ufw limit ssh` emits two rules, a
  `--set` and an `--update --seconds 30 --hitcount 6`. The first is skipped
  correctly (an unresolvable match in a rule with no verdict cannot change
  traversal), but the second needs `xt_recent_mtinfo` decoded to know it is an
  update rather than a set. Until then a rate-limited port reports `unknown`.
  On the reference host this is port 22.
- **Native nftables expressions poison the verdict.** Any expression
  `internal/collect` does not case becomes `facts.ExprUnknown`, which is the
  correct conservative answer but means a firewalld or hand-written nft host
  reports `unknown` widely. iptables-nft hosts (UFW, Docker) are unaffected.
  Decoding `expr.Ct`, `expr.Lookup` and `expr.Range` would cover most of it.
- **The nftables library drops expressions it cannot name** before whyopen
  ever sees them (`expr/expr.go` returns nil and the parser continues). A
  native `rt`, `last`, `socket`, `tproxy` or `osf` expression is invisible
  rather than unknown. This lives in the dependency and is the one remaining
  silently-dropped path.

## Modelling gaps that can produce a wrong answer

- **`addrtype` masks carrying an unnamed bit are reported as fully decoded.**
  `addrTypeNames` names 6 of the 12 type bits, so `--dst-type LOCAL,BLACKHOLE`
  becomes `["local"]` with `Decoded` true. Same class as the invert-flag defect
  fixed in the core plan. A mask check against the union of named bits closes it.
- **Forwarding is read from the global toggle only.** A host with
  `net.ipv4.ip_forward=0` but a per-interface `conf.<if>.forwarding=1` is
  reported `filtered` while genuinely forwarding.
- **An unreadable sysctl is indistinguishable from a false one.**
  `facts.Sysctls` has no tri-state, so a failed read defaults to false plus a
  warning. Deliberate: widening the schema was judged not worth the ripple
  while the failure direction is under-reporting.
- **Ingress base chains poison every hook.** `NF_INET_INGRESS` (hook 5) is
  named `unknown`, which correctly makes verdicts unknown rather than wrong,
  but naming and modelling the hook would be better.

## Robustness

- **`check --facts` trusts its input.** An arbitrary JSON document can reach
  a nil dereference (for example `{"kind":"xt"}` with no `xt` object). External
  input needs validating at the boundary.
- **A rule skipped as harmless records no `Hit`,** so it is invisible in
  `--explain`, even though a nearly-unresolvable rule is often the one a reader
  most wants to see.
- **`SchemaVersion` stayed 1 across two additive fields** (`Ruleset.ReadFailed`,
  `Expr` kind `unknown`). A facts document captured by an older binary still
  records set lookups as `other` and will be evaluated with the old, optimistic
  reading. Anyone diffing stored snapshots across versions should recapture.

## Not yet done

- **No golden fixture exists.** The plan's file structure promised
  `testdata/facts/*.json` and none was committed, so no test exercises a
  realistic full-size document end to end. A snapshot from a real host must be
  redacted first: it carries public addresses, container names and the entire
  ruleset, and this repository is public.
- **The README's sample verdict table is synthesised**, not captured from a
  real run.
