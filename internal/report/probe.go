package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MemorManeo/whyopen/internal/probe"
)

// Probe prints what a probe run found that the model did not, which is
// the whole reason to run one. A disagreement means either the model is
// missing something or something upstream is, and which one decides where
// the reader goes looking, so the diagnosis prints with it rather than
// leaving them to work it out from two verdicts.
func Probe(w io.Writer, dis []probe.Disagreement, source string) {
	if len(dis) == 0 {
		fmt.Fprintf(w, "\nprobe from %s: the model and reality agree on every port probed\n", source)
		return
	}
	fmt.Fprintf(w, "\nprobe from %s: %d port(s) where the model and reality disagree\n", source, len(dis))
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tFAMILY\tMODELLED\tPROBED\tWHAT THAT MEANS")
	for _, d := range dis {
		fmt.Fprintf(tw, "%d/%s\t%s\t%s\t%s\t%s\n", d.Port, d.Proto, family(d.Family), d.Modelled, d.Probed, d.Diagnosis)
	}
	tw.Flush()
}
