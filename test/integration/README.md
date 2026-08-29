# Integration suite

These tests exercise whyopen against a real kernel: they create network
namespaces, apply real UFW-shaped, Docker-shaped and firewalld-shaped
rulesets, run the real binary inside them and assert on what it reports.
One of them drives a real Docker daemon on the host's own network.

They are excluded from the default build by the `integration` tag, so
`go test ./...` never runs them and never touches your machine.

**This suite mutates the host it runs on.** The shipped code stays
strictly read-only; only these tests change anything.

## Running it

```
sudo -E go test -tags integration ./test/integration/
```

`sudo` usually resets `PATH` (`secure_path` in `/etc/sudoers`), which loses
the Go toolchain. If `sudo -E` cannot find `go`, pass the path through
explicitly, as CI does:

```
sudo -E env "PATH=$PATH" go test -tags integration ./test/integration/ -v
```

Add `-run TestName` to run a single test. `-v` is worth it: several tests
log the ruleset and the raw expression census they captured, which is the
evidence behind `docs/decisions/0003` and `0004`.

### Requirements

- **Real root.** Unprivileged user namespaces are not enough: many
  distributions restrict them, and the suite needs to create network
  namespaces, write sysctls and load nftables rules. Without root, every
  test calls `t.Skip` and the run is green but empty, which is why CI fails
  the job if it sees a `--- SKIP` line.
- **Linux**, with a kernel that has nftables.
- On `PATH`: `ip`, `iptables` (nft backend), `nft`, `python3`, `sysctl`,
  and `docker` for the one Docker test. Each test skips individually if a
  tool it needs is missing.

## What it does to the host

Most tests confine themselves to a throwaway network namespace named
`wo<pid>` joined to the host by a veth pair, and delete both on cleanup.
Inside that namespace they create bridges, add addresses from the
documentation range `203.0.113.0/24`, set `net.ipv4.ip_forward`, load
iptables and nft rulesets and start a `python3` listener. A run killed
mid-flight (a CI timeout, a Ctrl-C) skips its own cleanup and leaves the
namespace and its veth behind; the harness pre-deletes both by name on the
next run, so this is self-healing rather than fatal.

The namespace tests read the root namespace's `net.ipv4.ip_forward` before
writing the namespace's own, and restore it on cleanup only if it actually
changed. `TestPublishIsFilteredWhenForwardingIsDisabled` asserts that it
did not change, so a leak into the host's global network state fails the
suite rather than passing quietly.

### The Docker test, which is not namespaced

> **Do not run `TestRealDockerPublishIsReported` on a machine you care
> about.** It runs against the host's own network, not a namespace, because
> running Docker inside a namespace is its own project. For the duration of
> the test it:
>
> - creates a dummy interface `whyopen0` carrying the global-scope address
>   `203.0.113.10/32`, which changes what whyopen reports about the host
>   itself while it exists;
> - starts an `nginx:alpine` container named `whyopen-integration` with
>   **port 18080 published on all interfaces** (`-p 0.0.0.0:18080:80`), so
>   for those seconds the host really is serving nginx to anything that can
>   reach it;
> - lets Docker write its own nat and filter rules into the host's live
>   ruleset, as any `docker run -p` does.
>
> It removes the container and the interface on cleanup, and pre-deletes
> both by name at the start in case a previous run was killed before it
> could. It is written for an ephemeral CI runner. Skip it elsewhere with
> `-skip TestRealDockerPublishIsReported`; it also skips itself when
> `docker` is not on `PATH`.

## What is here

| file | contents |
|---|---|
| `harness_test.go` | builds the binary once, namespace and command helpers, `collectIn` |
| `ruleset_test.go` | the UFW, Docker-publish, DOCKER-USER, loopback-bind, forwarding-disabled and `ufw limit ssh` cases |
| `docker_test.go` | the one test that drives a real Docker daemon |
| `capture_test.go` | captures raw kernel bytes and expression censuses; the evidence behind decisions 0003 and 0004, and the guard that keeps those records honest |
