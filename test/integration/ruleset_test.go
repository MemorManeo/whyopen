//go:build integration && linux

package integration

import (
	"os"
	"strings"
	"testing"
)

// listenIn starts a listener bound to bindIP inside the namespace so the
// port has a real socket behind it, and returns once it is up.
func listenIn(t *testing.T, ns string, bindIP string, port string) {
	t.Helper()
	// nc is not universally present; python3 is, on every runner and on the
	// development host. A background listener dies with the namespace.
	script := "import socket,sys\n" +
		"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n" +
		"s.bind(('" + bindIP + "'," + port + "));s.listen(1)\n" +
		"sys.stderr.write('up\\n');sys.stderr.flush()\n" +
		"import time;time.sleep(300)\n"
	startBackground(t, ns, "up", "python3", "-c", script)
}

// A UFW-shaped ruleset: default deny on INPUT, an established accept that
// cannot match a fresh SYN, and one explicitly accepted port.
func TestUFWShapedRulesetAcceptsOnlyTheAllowedPort(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3")

	ns := newNetns(t)
	listenIn(t, ns, "0.0.0.0", "8080")
	listenIn(t, ns, "0.0.0.0", "9090")

	// iptables here is the nft backend, so these arrive as xt-compat
	// expressions exactly as UFW's do on a real host.
	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT")

	vs := evaluate(collectIn(t, ns))

	allowed := verdictFor(vs, 8080, "ip")
	if allowed == nil {
		t.Fatalf("no verdict for 8080, got %d verdicts", len(vs))
	}
	if allowed.Result != "reachable" {
		t.Errorf("8080 = %s (%s), want reachable", allowed.Result, allowed.Reason)
	}

	denied := verdictFor(vs, 9090, "ip")
	if denied == nil {
		t.Fatalf("no verdict for 9090")
	}
	if denied.Result != "filtered" {
		t.Errorf("9090 = %s (%s), want filtered", denied.Result, denied.Reason)
	}
}

// dockerShapedNetns builds what Docker builds: a bridge holding the container
// subnet, a DOCKER chain in nat reached from PREROUTING for locally destined
// traffic, and a DOCKER chain in filter reached from FORWARD. The bridge name
// is 15 bytes, the kernel maximum, matching the shape of a real br-<hash>.
//
// forwarding sets net.ipv4.ip_forward explicitly inside the namespace, to 1
// when true and to 0 when false. A namespace's default for this sysctl is
// not dependable: depending on net.core.devconf_inherit_init_net and the
// kernel, a fresh namespace can inherit whatever the root namespace already
// has rather than starting at the compiled-in default, so a CI runner with
// Docker already installed can hand out namespaces that start at 1. This
// suite never relies on that default in either direction; every caller sets
// the value it needs.
//
// It returns the root namespace's ip_forward value as read before that write,
// so a caller asserting isolation compares against what this host actually
// had rather than against a literal: a host without Docker, or a hardened
// one, legitimately sits at 0.
func dockerShapedNetns(t *testing.T, forwarding bool) (ns string, bridge string, rootForwarding string) {
	t.Helper()
	ns = newNetns(t)
	bridge = "br-000000000001"

	nsRun(t, ns, "ip", "link", "add", bridge, "type", "bridge")
	nsRun(t, ns, "ip", "addr", "add", "172.20.0.1/16", "dev", bridge)
	nsRun(t, ns, "ip", "link", "set", bridge, "up")

	// Whether this write actually lands on the namespace or, in some
	// environment, leaks to the root namespace, this suite must never
	// leave the host's global network configuration different from how it
	// found it. Capture the root namespace's value directly (no ip netns
	// exec, so this reads the root namespace regardless of where the write
	// below lands).
	before, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatalf("read root /proc/sys/net/ipv4/ip_forward before setting namespace forwarding: %v", err)
	}
	t.Cleanup(func() {
		// Restore only if the value actually moved. Isolation is proven by
		// TestPublishIsFilteredWhenForwardingIsDisabled, so an unconditional
		// write back can no longer repair anything, only introduce drift of
		// its own, and its error must not be swallowed when it does run.
		now, readErr := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
		if readErr != nil {
			t.Errorf("read root /proc/sys/net/ipv4/ip_forward during cleanup: %v", readErr)
			return
		}
		if string(now) == string(before) {
			return
		}
		t.Logf("root net.ipv4.ip_forward moved from %q to %q during this test; restoring it",
			strings.TrimSpace(string(before)), strings.TrimSpace(string(now)))
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", before, 0o644); err != nil {
			t.Errorf("restore root /proc/sys/net/ipv4/ip_forward to %q: %v",
				strings.TrimSpace(string(before)), err)
		}
	})
	want := "0"
	if forwarding {
		want = "1"
	}
	nsRun(t, ns, "sysctl", "-w", "net.ipv4.ip_forward="+want)

	nsRun(t, ns, "iptables", "-t", "nat", "-N", "DOCKER")
	nsRun(t, ns, "iptables", "-t", "nat", "-A", "PREROUTING",
		"-m", "addrtype", "--dst-type", "LOCAL", "-j", "DOCKER")
	nsRun(t, ns, "iptables", "-N", "DOCKER")
	nsRun(t, ns, "iptables", "-N", "DOCKER-USER")
	nsRun(t, ns, "iptables", "-A", "FORWARD", "-j", "DOCKER-USER")
	nsRun(t, ns, "iptables", "-A", "FORWARD", "-m", "conntrack",
		"--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	nsRun(t, ns, "iptables", "-A", "FORWARD", "-j", "DOCKER")
	nsRun(t, ns, "iptables", "-A", "DOCKER-USER", "-j", "RETURN")
	return ns, bridge, strings.TrimSpace(string(before))
}

// publishOnAllInterfaces adds the nat and filter rules Docker writes for
// `-p 0.0.0.0:host:container`.
func publishOnAllInterfaces(t *testing.T, ns, bridge, hostPort, containerIP, containerPort string) {
	t.Helper()
	nsRun(t, ns, "iptables", "-t", "nat", "-A", "DOCKER",
		"!", "-i", bridge, "-p", "tcp", "--dport", hostPort,
		"-j", "DNAT", "--to-destination", containerIP+":"+containerPort)
	nsRun(t, ns, "iptables", "-A", "DOCKER",
		"-d", containerIP, "!", "-i", bridge, "-o", bridge,
		"-p", "tcp", "--dport", containerPort, "-j", "ACCEPT")
}

// The canonical trap, against a real kernel: UFW denies by default on INPUT,
// and a container published on all interfaces is still reachable, because the
// packet is DNAT'd in prerouting and then handled in forward.
//
// whyopen derives endpoints only from listening sockets in /proc/net and from
// Docker publishes read through the Docker API. No Docker daemon runs inside
// this namespace, so without a real listener bound to the host port there
// would be no endpoint for 5432 at all; docker-proxy binding the host port on
// a real host is exactly what this listener stands in for.
func TestPublishOnAllInterfacesIsReachableDespiteInputDeny(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3", "sysctl")

	ns, bridge, _ := dockerShapedNetns(t, true)
	listenIn(t, ns, "0.0.0.0", "5432")
	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-P", "FORWARD", "DROP")
	publishOnAllInterfaces(t, ns, bridge, "5432", "172.20.0.2", "5432")

	v := verdictFor(evaluate(collectIn(t, ns)), 5432, "ip")
	if v == nil {
		t.Fatal("no verdict for the published port")
	}
	if v.Result != "reachable" {
		t.Fatalf("published port = %s, want reachable: %s", v.Result, v.Reason)
	}
	var sawForward, sawInput bool
	for _, h := range v.Path {
		switch h.Hook {
		case "forward":
			sawForward = true
		case "input":
			sawInput = true
		}
	}
	if !sawForward || sawInput {
		t.Errorf("path hooks wrong (forward=%v input=%v): the DNAT'd packet must take the forward hook only",
			sawForward, sawInput)
	}
}

// A DOCKER-USER deny is the documented way to close a publish without
// unpublishing it, and it must win. As above, the listener bound to the host
// port stands in for docker-proxy: without it there is no endpoint for 5432
// to evaluate at all.
func TestDockerUserDenyOverridesThePublish(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3", "sysctl")

	ns, bridge, _ := dockerShapedNetns(t, true)
	listenIn(t, ns, "0.0.0.0", "5432")
	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-P", "FORWARD", "DROP")
	publishOnAllInterfaces(t, ns, bridge, "5432", "172.20.0.2", "5432")
	// Insert ahead of the RETURN that dockerShapedNetns installed.
	nsRun(t, ns, "iptables", "-I", "DOCKER-USER", "1",
		"-p", "tcp", "--dport", "5432", "-j", "DROP")

	v := verdictFor(evaluate(collectIn(t, ns)), 5432, "ip")
	if v == nil {
		t.Fatal("no verdict for the published port")
	}
	if v.Result != "filtered" {
		t.Fatalf("published port = %s, want filtered by DOCKER-USER: %s", v.Result, v.Reason)
	}
	var sawDockerUserDrop bool
	for _, h := range v.Path {
		if h.Chain == "DOCKER-USER" && h.Action == "drop" {
			sawDockerUserDrop = true
		}
	}
	if !sawDockerUserDrop {
		t.Errorf("path never shows a drop in DOCKER-USER: filtered for some other reason, not the deny this test installs: %+v", v.Path)
	}
}

// A publish bound to loopback is the remediated shape and must be filtered
// for the bind reason, before any rule is consulted. The listener binds to
// 127.0.0.1, which is what a `-p 127.0.0.1:5432:5432` publish looks like from
// /proc: a real docker-proxy would bind there too, and it is the only source
// of an endpoint for 5432 in a namespace with no Docker daemon.
func TestPublishOnLoopbackIsFiltered(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3", "sysctl")

	ns, bridge, _ := dockerShapedNetns(t, true)
	listenIn(t, ns, "127.0.0.1", "5432")
	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-P", "FORWARD", "DROP")
	nsRun(t, ns, "iptables", "-t", "nat", "-A", "DOCKER",
		"-d", "127.0.0.1", "!", "-i", bridge, "-p", "tcp", "--dport", "5432",
		"-j", "DNAT", "--to-destination", "172.20.0.2:5432")

	v := verdictFor(evaluate(collectIn(t, ns)), 5432, "ip")
	if v == nil {
		t.Fatal("no verdict for the loopback-bound publish")
	}
	if v.Result != "filtered" {
		t.Fatalf("loopback-bound publish = %s, want filtered: %s", v.Result, v.Reason)
	}
	if len(v.Path) != 0 {
		t.Errorf("path is non-empty (%+v): a bind-address mismatch must be decided before any rule is consulted", v.Path)
	}
	if !strings.Contains(v.Reason, "bound to") {
		t.Errorf("reason does not name the bind: %s", v.Reason)
	}
}

// The forwarding check has, until now, only ever run against a facts
// document assembled by hand in Go. This proves it against a real kernel: a
// namespace with forwarding explicitly disabled models a host Docker has
// never touched. The packet is still DNAT'd in prerouting, since that
// decision does not consult the sysctl, but the rewritten destination is
// off-host and the kernel never routes it on, so it must be reported
// filtered for that reason rather than reachable.
//
// A namespace's default for this sysctl is not dependable (see
// dockerShapedNetns), so this test does not trust the default: it asserts
// isolation actually held, both that the namespace really reads back 0 and
// that setting it there did not also change the root namespace's value,
// before trusting any verdict built on top of it.
func TestPublishIsFilteredWhenForwardingIsDisabled(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3", "sysctl")

	ns, bridge, rootForwarding := dockerShapedNetns(t, false)

	// dockerShapedNetns(t, false) already set net.ipv4.ip_forward=0 inside
	// the namespace. Confirm isolation held rather than assuming it: if the
	// namespace does not read back 0, or if the root namespace no longer
	// reads what it read before that write, the sysctl is not isolated the
	// way every verdict below depends on it being.
	nsCat := nsRun(t, ns, "cat", "/proc/sys/net/ipv4/ip_forward")
	t.Logf("namespace /proc/sys/net/ipv4/ip_forward (cat via ip netns exec) = %q", strings.TrimSpace(nsCat))
	if got := strings.TrimSpace(nsCat); got != "0" {
		t.Fatalf("namespace net.ipv4.ip_forward = %q after setting it to 0, want 0", got)
	}
	nsSysctl := nsRun(t, ns, "sysctl", "-n", "net.ipv4.ip_forward")
	t.Logf("namespace net.ipv4.ip_forward (sysctl -n via ip netns exec) = %q", strings.TrimSpace(nsSysctl))
	if got := strings.TrimSpace(nsSysctl); got != "0" {
		t.Fatalf("namespace sysctl -n net.ipv4.ip_forward = %q after setting it to 0, want 0", got)
	}
	rootVal, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		t.Fatalf("read root /proc/sys/net/ipv4/ip_forward: %v", err)
	}
	t.Logf("root namespace /proc/sys/net/ipv4/ip_forward (os.ReadFile, no ip netns exec) = %q", strings.TrimSpace(string(rootVal)))
	if got := strings.TrimSpace(string(rootVal)); got != rootForwarding {
		t.Fatalf("root namespace net.ipv4.ip_forward = %q, want %q, the value it held before the namespace write: setting the test namespace's forwarding to 0 mutated the host's global network state instead of staying isolated to the namespace", got, rootForwarding)
	}

	listenIn(t, ns, "0.0.0.0", "5432")
	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-P", "FORWARD", "DROP")
	publishOnAllInterfaces(t, ns, bridge, "5432", "172.20.0.2", "5432")

	f := collectIn(t, ns)

	// Diagnostics for the open question of where net.ipv4.ip_forward is
	// actually being read from and written to. Logged unconditionally, so
	// they appear whether or not the assertions below pass, per Ruling 13.
	t.Logf("collected f.Host.Sysctls.IPv4Forward = %v", f.Host.Sysctls.IPv4Forward)
	for _, w := range f.Warnings {
		if w.Source == "host" {
			t.Logf("host warning: %s", w.Message)
		}
	}

	v := verdictFor(evaluate(f), 5432, "ip")
	if v == nil {
		t.Fatal("no verdict for the published port")
	}
	if v.Result != "filtered" {
		t.Fatalf("published port = %s, want filtered while forwarding is disabled: %s", v.Result, v.Reason)
	}
	if !strings.Contains(v.Reason, "forward") {
		t.Fatalf("reason does not mention forwarding, so this may be filtered for the wrong cause: %s", v.Reason)
	}
}

// The headline claim of this plan: ufw limit ssh's two rules, --set with no
// verdict and --update carrying the drop, decode and resolve port 22 as
// reachable instead of unknown. Unlike TestConvertRecentSetAndUpdate, which
// decodes a hex constant frozen from one past capture, this asserts the
// decoder against a payload the kernel writes right now, so a future kernel
// or iptables version that changed the layout would show up here even if
// nobody thought to recapture the hex constants.
func TestUFWLimitSSHResolvesReachable(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3")

	ns := newNetns(t)
	listenIn(t, ns, "0.0.0.0", "22")

	nsRun(t, ns, "iptables", "-P", "INPUT", "DROP")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
		"-m", "conntrack", "--ctstate", "NEW", "-m", "recent", "--set", "--name", "SSH")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22",
		"-m", "conntrack", "--ctstate", "NEW",
		"-m", "recent", "--update", "--seconds", "30", "--hitcount", "6", "--name", "SSH",
		"-j", "DROP")
	nsRun(t, ns, "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT")

	v := verdictFor(evaluate(collectIn(t, ns)), 22, "ip")
	if v == nil {
		t.Fatal("no verdict for port 22")
	}
	if v.Result != "reachable" {
		t.Fatalf("port 22 = %s (%s), want reachable: whyopen's synthetic packet is a first "+
			"connection from a source the recent list has never seen, so --set matches (and "+
			"carries no verdict) and --update does not match, leaving the final ACCEPT to decide",
			v.Result, v.Reason)
	}
}
