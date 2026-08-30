# Patches whyopen owes upstream

`internal/collect/chaindev.go` exists because `github.com/google/nftables`
writes `NFTA_HOOK_DEV` when it adds a chain and drops it when it reads one
back, so a chain collected from a live kernel never says which device its
hook is attached to. Decision 0006 permitted whyopen to issue its own
netlink read to recover that, and said plainly what should happen next:

> The patch belongs upstream. When `google/nftables` reads the attribute
> itself, `chaindev.go` and this decision's exception should be deleted
> rather than kept as a second source of the same truth.

`nftables-hook-devices.patch` is that patch, and it is not yet submitted.
Submitting it is a decision for the repository owner, not something
whyopen's tooling does on its own.

It is rebased onto upstream `main` at `f9b52ed` ("userdata: fix
out-of-bounds panic in Get (#359)", 38 commits past v0.3.0), where it
applies with a plain `git am`, and it carries the commit message the pull
request should have. Rebase it again if it goes stale before it is sent.

## What it does

`hookFromMsg` reads `NFTA_HOOK_DEV` and the `NFTA_HOOK_DEVS` list, and
`chainFromMsg` puts them on the chain. `Chain` gains `Devices []string`
alongside the existing `Device`, because a netdev chain can be attached to
several interfaces at once (`devices = { eth0, eth1 }`) and one string
cannot say so. `AddChain` marshals the list when there is one, so a chain
now round-trips through add and get. Setting `Device` alone behaves
exactly as before.

## What was checked

Re-checked on 2026-08-30 against `main` at `f9b52ed`, not only against
the v0.3.0 the patch was first written on:

- The patch applies to that commit with `git am`, no three-way merge and
  no conflict.
- The library's own test suite passes, and `gofmt` and `go vet` are clean
  on the patched tree.
- Its three new tests run and pass: the single-device attribute, the
  nested `NFTA_HOOK_DEVS` list, and a chain with no device at all.
- whyopen builds and its whole unit suite passes against the patched
  library, through a temporary `replace` directive, so the API change is
  compatible with at least one real consumer.

Not checked: the patched library against a live kernel. whyopen's own
integration suite covers that path through `chaindev.go`, and the two
agree on the wire format, but nobody has run the patched library itself
against a kernel with an ingress chain.

## Submitting it

```
git clone https://github.com/google/nftables && cd nftables
git checkout -b hook-devices
git am /path/to/nftables-hook-devices.patch
gh pr create --title "chain: read the hook device attributes back" --body-file <(...)
```

The patch is authored as the repository owner, so the commit needs no
`--author` fixing before it is sent.

Suggested PR body:

> `AddChain` marshals `NFTA_HOOK_DEV`, but `hookFromMsg` reads only the
> hook number and the priority, so a chain read back from the kernel never
> carries the device its hook is attached to. That makes an ingress or
> egress chain indistinguishable from one attached to every device.
>
> This reads `NFTA_HOOK_DEV` and the `NFTA_HOOK_DEVS` list, and adds
> `Chain.Devices` for the multi-device case that a single string cannot
> represent. `AddChain` marshals the list when one is set, so such a chain
> round-trips. Setting `Device` alone is unchanged.
>
> Found while writing a tool that reads rulesets over netlink: without the
> device, an ingress chain has to be treated as seeing every packet, which
> makes every verdict on such a host unusable.
