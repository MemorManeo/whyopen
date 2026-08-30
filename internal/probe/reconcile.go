package probe

import (
	"fmt"

	"github.com/MemorManeo/whyopen/internal/model"
)

// Disagreement is a port where the model and the probe do not tell the
// same story. It is the most valuable thing a probe produces: either the
// model is missing something, or something between the probe and the host
// is, and which one it is decides where the operator goes looking.
type Disagreement struct {
	Port      uint16
	Proto     string
	Family    string
	Modelled  string
	Probed    State
	Diagnosis string
}

// Reconcile folds probe results into a verdict set, with the probe
// authoritative for TCP: it found out, the model concluded.
//
// It touches only TCP verdicts of the family that was probed. UDP is left
// model-only, because a TCP probe says nothing about it and an unanswered
// UDP probe says almost nothing about anything. A probe that errored is
// ignored entirely: not finding out is not evidence.
//
// The probe answers a question about an address and a port, not about a
// socket, so when several sockets share a port the same answer lands on
// all of them and the reason says whyopen cannot tell which one answered.
func Reconcile(vs []model.Verdict, rs []Result, family, target string) ([]model.Verdict, []Disagreement) {
	byPort := map[uint16]Result{}
	for _, r := range rs {
		if r.Proto == "tcp" && r.State != StateError {
			byPort[r.Port] = r
		}
	}

	// How many verdicts share each probed port, so the reason can say when
	// the answer cannot be pinned to one socket.
	sockets := map[uint16]int{}
	for _, v := range vs {
		if v.Endpoint.Proto == "tcp" && v.Family == family {
			sockets[v.Endpoint.Port]++
		}
	}

	out := make([]model.Verdict, len(vs))
	copy(out, vs)
	var dis []Disagreement
	seen := map[uint16]bool{}

	for i, v := range out {
		if v.Endpoint.Proto != "tcp" || v.Family != family {
			continue
		}
		r, ok := byPort[v.Endpoint.Port]
		if !ok {
			continue
		}
		result := "filtered"
		if r.State == StateOpen {
			result = "reachable"
		}

		reason := fmt.Sprintf("probed %s:%d and it is %s", target, v.Endpoint.Port, probeWord(r.State))
		if sockets[v.Endpoint.Port] > 1 {
			reason += ", though this port has several sockets and whyopen cannot tell which socket answered"
		}
		if v.Result != "unknown" && v.Result != result {
			reason = fmt.Sprintf("%s, but whyopen read the ruleset as %s", reason, v.Result)
			if !seen[v.Endpoint.Port] {
				seen[v.Endpoint.Port] = true
				dis = append(dis, Disagreement{
					Port: v.Endpoint.Port, Proto: "tcp", Family: family,
					Modelled: v.Result, Probed: r.State,
					Diagnosis: diagnose(v.Result, r.State),
				})
			}
		}
		out[i].Result = result
		out[i].Reason = reason
	}
	return out, dis
}

func probeWord(s State) string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "refused, so something answered with a reset rather than dropping the packet"
	}
	return "filtered: nothing answered before the timeout"
}

func diagnose(modelled string, probed State) string {
	if probed == StateOpen {
		return "the port is open and whyopen read the ruleset as closing it, so the model is missing something: an interface, a hook or an expression it does not follow. Treat the port as open and the model as wrong"
	}
	if modelled == "reachable" {
		return "the ruleset on this host allows it, and nothing answered from where the probe ran, so something between the probe and this host stops it: a provider firewall, a cloud security group, an upstream NAT. Nothing on this host will show it"
	}
	return "the model and the probe disagree"
}
