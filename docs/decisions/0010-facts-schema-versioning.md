# 0010: What a facts schema version means, and when it moves

Date: 2026-08-30
Status: accepted
Resolves: the last thing 1.0 would freeze without a written rule.

## Question

`facts.SchemaVersion` has been 1 since the first commit, through every
field added since: sets and set elements (0005), preserved xt payloads
(0007), chain hook devices (0006), per-interface forwarding. One field was
renamed outright, `Chain.Device` to `Chain.Devices` in v0.5.0, and the
version did not move for that either, on the reasoning that no live
collection had ever populated the old one so nothing in the world could
notice.

Pre-1.0 that is defensible. At 1.0 the version becomes a promise to
whoever holds a document, and the promise has never been written down.
Worse, the code contradicted the intent behind it: `check` refused any
document whose version was not exactly this build's, so the first bump
would have made every whyopen refuse every document every earlier whyopen
ever wrote. That is the direct opposite of what the preserved payloads
exist for, which is a snapshot collected once and evaluated later by a
build that reads it better.

## Decision

**The version answers one question: does a reader need new code to read
this document safely?**

A bump is required when a field is removed or renamed, when a field's
meaning or units change, or when the absence of a field starts to mean
something other than "the collecting build did not record this".

A bump is *not* required to add an optional field. An older reader ignores
what it does not know, and a newer reader must read absence as "not
collected", never as a fact about the host. Every change since v0.1 has
been of this kind, which is why the version has not moved and why it
should not have.

**Older is readable; newer is refused.** `facts.SupportedSchema` accepts
any version from 1 up to this build's own, and refuses anything above it,
because a build cannot know what changed in a document from a later one
and reading it on the assumption that nothing important did is how a tool
produces a confident wrong answer. A missing or zero version is refused as
not being a facts document at all, which also catches the ordinary mistake
of pointing `--facts` at some other JSON file.

**The migration comes before the bump.** Whatever a bump breaks, the code
that lets this build read the older document has to exist in the same
change that raises the number, not in the one after it. A version that
readers cannot act on is worse than no version.

**The rename in v0.5.0 stays unbumped, and is the last of its kind.**
`device` to `devices` was safe only because nothing had ever written the
old field, which is a claim that could be checked at the time and can
never be checked again once documents are in the wild. After 1.0 a rename
takes a bump regardless of how confident anyone is that nobody noticed.

## Consequence

The version is a real signal instead of an unused field: it moves rarely,
it moves for one reason, and when it moves the reader already knows what
to do. 1.0 can freeze the schema without freezing the ability to add to it.
