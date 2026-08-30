package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
)

// order puts the findings that matter first. Nobody scrolls to find the open
// port.
var order = map[string]int{"reachable": 0, "unknown": 1, "filtered": 2}

// worstFirst copies the verdicts into the order both output modes print
// them in, so a script reading --json sees the same ranking a person
// reading the table does.
func worstFirst(vs []model.Verdict) []model.Verdict {
	sorted := make([]model.Verdict, len(vs))
	copy(sorted, vs)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && order[sorted[j].Result] < order[sorted[j-1].Result]; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted
}

func Table(w io.Writer, vs []model.Verdict, warns []facts.Warning) {
	sorted := worstFirst(vs)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RESULT\tPORT\tFAMILY\tOWNER\tBIND\tWHY")
	for _, v := range sorted {
		fmt.Fprintf(tw, "%s\t%d/%s\t%s\t%s\t%s\t%s\n",
			v.Result, v.Endpoint.Port, v.Endpoint.Proto, family(v.Family),
			dash(v.Endpoint.Owner), dash(v.Endpoint.BindIP), v.Reason)
	}
	tw.Flush()

	if len(warns) > 0 {
		fmt.Fprintln(w, "\nwarnings (the snapshot is incomplete, verdicts above may be too):")
		for _, x := range warns {
			fmt.Fprintf(w, "  %s: %s\n", x.Source, x.Message)
		}
	}
}

// Explain prints the ordered rule path behind one verdict.
func Explain(w io.Writer, v model.Verdict) {
	fmt.Fprintf(w, "%d/%s over %s is %s\n  %s\n\n",
		v.Endpoint.Port, v.Endpoint.Proto, family(v.Family), v.Result, v.Reason)
	if len(v.Path) == 0 {
		fmt.Fprintln(w, "  no rule was reached")
		return
	}
	for i, h := range v.Path {
		note := ""
		if h.Action == "skipped" {
			// Without this the rule reads as though it decided something.
			note = ", skipped: it carries no verdict, so neither outcome of its unresolved match changes the path"
		}
		fmt.Fprintf(w, "  %2d. %s %s/%s (hook %s, priority %d, handle %d%s)\n      %s\n",
			i+1, h.Family, h.Table, h.Chain, h.Hook, h.Priority, h.Handle, note, RenderRule(h.Rule))
	}
}

func family(f string) string {
	if f == "ip6" {
		return "IPv6"
	}
	return "IPv4"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
