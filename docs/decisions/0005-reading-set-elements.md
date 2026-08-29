# 0005: Widen the read-only whitelist to GetSets and GetSetElements

Date: 2026-08-29
Status: accepted
Resolves: decoding `expr.Lookup`, the last item
`docs/decisions/0004-firewalld-expressions.md` left open for closing the
firewalld gap.

## Question

Decision 0001 fixed the read-only contract in its most concrete form: the
only `*nftables.Conn` methods whyopen may call, anywhere, are `ListTables`,
`ListChainsOfTableFamily` and `GetRules`. That whitelist has held unchanged
through v0.1 and the v0.2 `Ct` decoder. Decoding `expr.Lookup` needs it to
move: a `Lookup` expression carries a set reference, a name for a named set
or an ID for an anonymous one (decision 0004's census), not the set's
elements. Resolving `tcp dport @zone_public_ports accept`, or the brace-list
`ct state { established, related } accept` that decision 0004 could not
close, means knowing what is actually in `zone_public_ports` or in the
anonymous set the second rule compiles to. Neither `ListTables`,
`ListChainsOfTableFamily` nor `GetRules` can produce that: none of them
reads a set at all. Without a fourth and fifth method, `Lookup` cannot be
decoded, full stop, and this has been raised and declined before as an
informal widening; it is being recorded properly instead.

## Decision

Widen the whitelist from three methods to five, adding `github.com/google/
nftables`'s `Conn.GetSets` and `Conn.GetSetElements`. `internal/collect/
ruleset.go`'s `rulesetSource` interface gains both, alongside the three it
already names, and no other file may call any `*nftables.Conn` method
outside that interface, exactly as before.

Both additions are reads. `GetSets(t *nftables.Table)` lists the sets of a
table, the direct sibling of `ListChainsOfTableFamily` for chains.
`GetSetElements(s *nftables.Set)` lists one set's elements, the direct
sibling of `GetRules` for a chain's rules. Neither method's netlink message
carries the request flags (`NLM_F_CREATE`, `NLM_F_REPLACE` or similar) that
would make it a write; both send a `NFT_MSG_GET*` request with the `Dump`
flag, the same shape `ListTables`, `ListChainsOfTableFamily` and `GetRules`
already send. Reading a fourth and fifth data type is a wider read, not a
different kind of operation.

## Why the read-only guarantee is unaffected

The guarantee decision 0001 exists to protect is that whyopen never creates,
modifies or deletes anything in the kernel's ruleset. That property is a
statement about which methods are called, not how many. `GetSets` and
`GetSetElements` are both pure reads, structurally verified the same way the
original three are: `rulesetSource` is an interface, so any call outside its
method set fails to compile against `*nftables.Conn`, and the interface
itself is the enforcement mechanism, not a convention someone has to
remember. `AddSet`, `SetAddElements`, `DelSet`, `FlushSet` and
`SetDeleteElements` all exist on `*nftables.Conn` and are not, and will not
be, part of `rulesetSource`.

## Consequences

- `rulesetSource` names five methods, not three. Any future addition needs
  its own decision record; this one authorizes exactly `GetSets` and
  `GetSetElements` and nothing else. A sixth method, on this connection or
  any other read handle whyopen ever opens, is out of scope until a
  further record makes the same case for it that this one makes for these
  two.
- `internal/collect/ruleset.go` reads a table's sets alongside its chains,
  following the same degradation posture as chain and rule reads: a failure
  reading sets or set elements becomes a `facts.Warning` and marks the
  ruleset read incomplete, rather than aborting the snapshot.
- `internal/facts` gains `Set` and `SetElement` as additive types
  (`facts.SchemaVersion` stays 1), and `expr.Lookup` decodes into a new
  `facts.LookupExpr`. What the evaluator is willing to resolve from a set's
  elements is scoped separately in `internal/model/match.go`'s own
  documentation: this record is about what whyopen is now permitted to
  read, not about what it resolves from what it reads.
