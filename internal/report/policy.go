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
	if !res.FailOnUnknown {
		// The main table already lists them, and here they change nothing.
		show = nil
	}
	if len(res.Violations) == 0 && len(res.Stale) == 0 && len(show) == 0 {
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
	tw.Flush()
}
