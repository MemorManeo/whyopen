//go:build integration && linux

package integration

import "testing"

// listenIn starts a listener inside the namespace so the port has a real
// socket behind it, and returns once it is up.
func listenIn(t *testing.T, ns string, port string) {
	t.Helper()
	// nc is not universally present; python3 is, on every runner and on the
	// development host. A background listener dies with the namespace.
	script := "import socket,sys\n" +
		"s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n" +
		"s.bind(('0.0.0.0'," + port + "));s.listen(1)\n" +
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
	listenIn(t, ns, "8080")
	listenIn(t, ns, "9090")

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
