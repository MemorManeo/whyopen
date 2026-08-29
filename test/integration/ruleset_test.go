//go:build integration && linux

package integration

import "testing"

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
func dockerShapedNetns(t *testing.T) (ns string, bridge string) {
	t.Helper()
	ns = newNetns(t)
	bridge = "br-000000000001"

	nsRun(t, ns, "ip", "link", "add", bridge, "type", "bridge")
	nsRun(t, ns, "ip", "addr", "add", "172.20.0.1/16", "dev", bridge)
	nsRun(t, ns, "ip", "link", "set", bridge, "up")

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
	return ns, bridge
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
	requireTools(t, "ip", "iptables", "python3")

	ns, bridge := dockerShapedNetns(t)
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
	requireTools(t, "ip", "iptables", "python3")

	ns, bridge := dockerShapedNetns(t)
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
}

// A publish bound to loopback is the remediated shape and must be filtered
// for the bind reason, before any rule is consulted. The listener binds to
// 127.0.0.1, which is what a `-p 127.0.0.1:5432:5432` publish looks like from
// /proc: a real docker-proxy would bind there too, and it is the only source
// of an endpoint for 5432 in a namespace with no Docker daemon.
func TestPublishOnLoopbackIsFiltered(t *testing.T) {
	requireRoot(t)
	requireTools(t, "ip", "iptables", "python3")

	ns, bridge := dockerShapedNetns(t)
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
}
