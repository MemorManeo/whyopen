# 0009: whyopen may send a packet, when asked by name

Date: 2026-08-30
Status: accepted
Recorded after the fact: shipped in v0.4.0. This is the only decision in
the project that changes what whyopen *does* rather than what it reads, and
it was made in a commit message, which is not where a change of posture
belongs.

## Question

Every other part of whyopen concludes what the kernel would do with a
packet by reading rules. The README's second-loudest claim is that it is
read-only, and the v0.1.0 release notes stated the limit plainly: "whyopen
reads a real ruleset and concludes what the kernel would do with a packet.
It does not send one."

That limit is also the tool's largest blind spot. A model can be wrong, and
when it is, nothing in the model can tell you. A host behind NAT or a cloud
security group is the ordinary case where the ruleset on the box is not the
thing deciding reachability, and reading it more carefully cannot help.

So: may a tool that advertises itself as read-only send a packet?

## Decision

Yes, when the user asks for it by name, and never otherwise.

**Read-only is about state, and stays true.** `whyopen probe` opens
ordinary TCP connections and closes them. It creates no rule, no socket
that outlives the run, and nothing on the host or the target. The README's
claim is qualified rather than quietly kept: it now says what probing does
and that it runs only when asked. The claim was worth qualifying rather
than dropping, because "changes nothing" is the property users actually
rely on.

**Nothing probes implicitly.** `probe` is its own subcommand, and `check`
probes only under `--probe-from`. No default, no heuristic, no "probe if it
looks safe".

**It is a connect probe, not a scanner.** One pass, no retries, a bounded
number of connections in flight, and a port spec refused past 4096 ports.
The refusal is the part that matters: it is what makes the tool unable to
be pointed at a network, and it is checked before anything is sent.

**Four states, because they are four different facts.** Open completed a
handshake. Closed was answered with a reset, so the packet reached the
host's TCP stack or a rule that rejects rather than drops. Filtered got no
answer. Error means whyopen could not find out, and is never read as
evidence about the port: a broken vantage point must not be able to
overrule the model.

**The probe is authoritative for TCP, and UDP stays model-only.** It found
out; the model concluded. UDP is left alone because a TCP probe says
nothing about it and an unanswered UDP probe says almost nothing about
anything.

**A disagreement carries its diagnosis.** The two directions mean opposite
things and send the operator to opposite places: the model saying filtered
where the probe gets in means whyopen is missing something, and the model
saying reachable where nothing answers means a firewall between the two
that nothing on the host will show. Reporting the pair without saying
which is which would leave the most valuable output of a probe run as a
puzzle.

**Reality reaches the policy.** Reconciliation happens before the policy
check, so a port the probe found open is a violation if the policy does not
allow it, whatever the ruleset was read to mean.

**A probe that could not run is a tool error, exit 3.** Never a quiet fall
back to the model: a run that silently did not check reality looks exactly
like one that did.

**The remote is reached over ssh, and the arguments are checked before it
is.** `--probe-from ssh://[user@]host[:port]` runs `whyopen probe` on that
machine. The target and the port list end up in a command that machine's
shell runs, so the target must parse as an IP address and the ports are
rendered from numbers, refused here rather than quoted and hoped for. The
ssh destination is refused if it contains shell metacharacters. whyopen
adds no ssh options of its own: the user's ssh config decides the key, the
port and the rest, which is the only sane place for that to live. The
runner is an interface, so all of this is tested without an ssh server.

## Consequence

whyopen can now tell you that it is wrong, which nothing else in it could
do. It requires whyopen on the vantage machine, and it says nothing about
UDP.

The scope limit is worth restating because it is the thing that could
erode: this is a self-audit tool that connects to a host you name. It has
no host discovery, no port sweep, no service detection, and no timing
options, and the absence of those is a decision rather than an omission.
