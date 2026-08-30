package probe

import (
	"strings"
	"testing"

	"github.com/MemorManeo/whyopen/internal/model"
)

func tcpVerdict(port uint16, family, result, bind string) model.Verdict {
	return model.Verdict{
		Endpoint: model.Endpoint{Port: port, Proto: "tcp", BindIP: bind},
		Family:   family,
		Result:   result,
		Reason:   "modelled",
	}
}

// The probe is authoritative for TCP: it found out, the model concluded.
func TestReconcileTakesTheProbeOverTheModel(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(8080, "ip", "filtered", "0.0.0.0")}
	got, dis := Reconcile(vs, []Result{{Port: 8080, Proto: "tcp", State: StateOpen}}, "ip", "203.0.113.10")
	if got[0].Result != "reachable" {
		t.Fatalf("result = %q, want reachable: the probe got in", got[0].Result)
	}
	if len(dis) != 1 {
		t.Fatalf("disagreements = %v, want one", dis)
	}
	if dis[0].Modelled != "filtered" || dis[0].Probed != StateOpen {
		t.Errorf("disagreement = %+v, want filtered against open", dis[0])
	}
	// The one that matters most: the model said closed and it is not.
	if !strings.Contains(dis[0].Diagnosis, "missing") {
		t.Errorf("diagnosis = %q, want it to say the model is missing something", dis[0].Diagnosis)
	}
}

// The other direction is not a bug in the model, it is a firewall the
// model cannot see, and the diagnosis has to say so or an operator will
// go looking in the wrong ruleset.
func TestReconcileExplainsAReachablePortTheProbeCannotReach(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(443, "ip", "reachable", "0.0.0.0")}
	got, dis := Reconcile(vs, []Result{{Port: 443, Proto: "tcp", State: StateFiltered}}, "ip", "203.0.113.10")
	if got[0].Result != "filtered" {
		t.Fatalf("result = %q, want filtered: nothing answered", got[0].Result)
	}
	if len(dis) != 1 || dis[0].Probed != StateFiltered {
		t.Fatalf("disagreements = %+v, want one naming the filtered probe", dis)
	}
	for _, want := range []string{"between", "this host"} {
		if !strings.Contains(dis[0].Diagnosis, want) {
			t.Errorf("diagnosis = %q, want it to point upstream (%q)", dis[0].Diagnosis, want)
		}
	}
}

// An unknown is not a disagreement. It is the case the probe exists to
// resolve, and resolving it is the whole point.
func TestReconcileResolvesAnUnknownWithoutCallingItADisagreement(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(22, "ip", "unknown", "0.0.0.0")}
	got, dis := Reconcile(vs, []Result{{Port: 22, Proto: "tcp", State: StateOpen}}, "ip", "203.0.113.10")
	if got[0].Result != "reachable" {
		t.Fatalf("result = %q, want reachable", got[0].Result)
	}
	if len(dis) != 0 {
		t.Fatalf("disagreements = %+v, want none: the model never claimed anything", dis)
	}
	if !strings.Contains(got[0].Reason, "203.0.113.10") {
		t.Errorf("reason = %q, want it to say where the probe ran against", got[0].Reason)
	}
}

// A refused connection is not the same as no answer, and the verdict says
// which one happened.
func TestReconcileDistinguishesRefusedFromDropped(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(22, "ip", "unknown", "0.0.0.0")}
	got, _ := Reconcile(vs, []Result{{Port: 22, Proto: "tcp", State: StateClosed}}, "ip", "203.0.113.10")
	if got[0].Result != "filtered" {
		t.Fatalf("result = %q, want filtered", got[0].Result)
	}
	if !strings.Contains(got[0].Reason, "refused") {
		t.Errorf("reason = %q, want it to say the connection was refused rather than dropped", got[0].Reason)
	}
}

// A probe that could not find out says nothing about the port, so it must
// not overwrite what the model concluded.
func TestReconcileIgnoresAProbeError(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(22, "ip", "reachable", "0.0.0.0")}
	got, dis := Reconcile(vs, []Result{{Port: 22, Proto: "tcp", State: StateError, Detail: "no route to host"}}, "ip", "203.0.113.10")
	if got[0].Result != "reachable" || got[0].Reason != "modelled" {
		t.Fatalf("verdict = %+v, want the model's own answer untouched", got[0])
	}
	if len(dis) != 0 {
		t.Fatalf("disagreements = %+v, want none", dis)
	}
}

// UDP is model-only: a TCP probe says nothing about it.
func TestReconcileLeavesUDPAlone(t *testing.T) {
	vs := []model.Verdict{{
		Endpoint: model.Endpoint{Port: 53, Proto: "udp"}, Family: "ip", Result: "reachable", Reason: "modelled",
	}}
	got, _ := Reconcile(vs, []Result{{Port: 53, Proto: "tcp", State: StateFiltered}}, "ip", "203.0.113.10")
	if got[0].Result != "reachable" {
		t.Fatalf("result = %q, want the UDP verdict untouched", got[0].Result)
	}
}

// A probe of one family says nothing about the other.
func TestReconcileLeavesTheOtherFamilyAlone(t *testing.T) {
	vs := []model.Verdict{tcpVerdict(443, "ip6", "reachable", "::")}
	got, _ := Reconcile(vs, []Result{{Port: 443, Proto: "tcp", State: StateFiltered}}, "ip", "203.0.113.10")
	if got[0].Result != "reachable" {
		t.Fatalf("result = %q, want the IPv6 verdict untouched by an IPv4 probe", got[0].Result)
	}
}

// A port with several sockets gets one answer from the probe, because the
// probe asks about the port, not about the socket. Saying so in the
// reason is the honest way to carry that: whyopen cannot tell which
// socket answered.
func TestReconcileSaysWhenAPortHasSeveralSockets(t *testing.T) {
	vs := []model.Verdict{
		tcpVerdict(53, "ip", "filtered", "127.0.0.53"),
		tcpVerdict(53, "ip", "filtered", "127.0.0.54"),
	}
	got, dis := Reconcile(vs, []Result{{Port: 53, Proto: "tcp", State: StateOpen}}, "ip", "203.0.113.10")
	if len(dis) != 1 {
		t.Fatalf("disagreements = %d, want one for the port, not one per socket", len(dis))
	}
	for _, v := range got {
		if !strings.Contains(v.Reason, "which socket") {
			t.Errorf("reason = %q, want it to say whyopen cannot tell which socket answered", v.Reason)
		}
	}
}
