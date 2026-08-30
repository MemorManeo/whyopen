package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MemorManeo/whyopen/internal/policy"
)

// Policy prints what the policy made of the verdicts, under the table
// they came from. It prints in every output mode, so an exit code the
// policy produced is never one the reader cannot see a reason for.
func Policy(w io.Writer, res policy.Result, source string) {
	show := res.Unknown
	// What never became a verdict is reported the same way, and under the
	// same condition: without fail_on_unknown it changes no exit code, and
	// the warnings block above already said it.
	blind := res.Unreadable
	if !res.FailOnUnknown {
		// The main table already lists them, and here they change nothing.
		show, blind = nil, nil
	}
	if len(res.Violations) == 0 && len(res.Stale) == 0 && len(show) == 0 && len(blind) == 0 {
		fmt.Fprintf(w, "\npolicy %s: every reachable port is allowed\n", source)
		return
	}

	fmt.Fprintf(w, "\npolicy %s\n", source)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY\tPORT\tFAMILY\tOWNER\tWHY")
	for _, v := range res.Violations {
		fmt.Fprintf(tw, "violation\t%d/%s\t%s\t%s\t%s\n",
			v.Endpoint.Port, v.Endpoint.Proto, family(v.Family), dash(v.Endpoint.Owner),
			"reachable, and the policy does not allow it")
	}
	for _, s := range res.Stale {
		why := "allowed, but nothing is listening"
		if s.Found != "" {
			why = "allowed, but " + s.Found
		}
		fmt.Fprintf(tw, "stale\t%s\t%s\t%s\t%s\n", s.Entry, "-", "-", why)
	}
	for _, v := range show {
		fmt.Fprintf(tw, "unknown\t%d/%s\t%s\t%s\t%s\n",
			v.Endpoint.Port, v.Endpoint.Proto, family(v.Family), dash(v.Endpoint.Owner),
			"unresolved, and fail_on_unknown is set")
	}
	for range blind {
		// No port to name: that is exactly what makes it unreadable. The
		// warning above carries the rule, so this says which line to go
		// read rather than repeating the sentence.
		fmt.Fprintf(tw, "unknown\t%s\t%s\t%s\t%s\n", "-", "-", "-",
			"a forward whyopen could not reduce to ports (see the warnings above), and fail_on_unknown is set")
	}
	tw.Flush()
}
